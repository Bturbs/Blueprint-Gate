#!/usr/bin/env python3
"""Install daily backup and weekly restore checks for the local macOS staging stack."""

from pathlib import Path
import os
import plistlib
import shutil
import subprocess


def main() -> None:
    if os.uname().sysname != "Darwin":
        raise SystemExit("This installer requires macOS launchd")
    root = Path(__file__).resolve().parent.parent
    runtime = Path.home() / ".local" / "share" / "blueprint-gate"
    bin_dir = runtime / "bin"
    log_dir = runtime / "logs"
    agent_dir = Path.home() / "Library" / "LaunchAgents"
    for directory in (runtime, bin_dir, log_dir, agent_dir):
        directory.mkdir(parents=True, exist_ok=True)
        if directory != agent_dir:
            directory.chmod(0o700)
    scripts = ("backup-postgres.sh", "test-postgres-restore.sh", "check-latest-postgres-backup.sh")
    for name in scripts:
        destination = bin_dir / name
        shutil.copy2(root / "scripts" / name, destination)
        destination.chmod(0o700)

    common_env = {
        "BLUEPRINT_GATE_DB_CONTAINER": os.environ.get("BLUEPRINT_GATE_DB_CONTAINER", "aiworkflow-db-1"),
        "HOME": str(Path.home()),
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
    }
    for name in ("BACKUP_DIR", "BACKUP_RETENTION_DAYS", "BACKUP_MAX_AGE_HOURS", "XDG_DATA_HOME"):
        if name in os.environ:
            common_env[name] = os.environ[name]
    jobs = (
        ("com.blueprintgate.staging.backup", "backup-postgres.sh", {"Hour": 2, "Minute": 0}),
        ("com.blueprintgate.staging.restore-check", "check-latest-postgres-backup.sh", {"Weekday": 0, "Hour": 3, "Minute": 0}),
    )
    domain = f"gui/{os.getuid()}"
    for label, script, calendar in jobs:
        plist = agent_dir / f"{label}.plist"
        payload = {
            "Label": label,
            "ProgramArguments": [str(bin_dir / script)],
            "WorkingDirectory": str(runtime),
            "EnvironmentVariables": common_env,
            "StartCalendarInterval": calendar,
            "StandardOutPath": str(log_dir / f"{label}.out.log"),
            "StandardErrorPath": str(log_dir / f"{label}.err.log"),
            "Umask": 0o077,
        }
        temporary = plist.with_suffix(".tmp")
        with temporary.open("wb") as stream:
            plistlib.dump(payload, stream)
        temporary.chmod(0o600)
        temporary.replace(plist)
        present = subprocess.run(["launchctl", "print", f"{domain}/{label}"], capture_output=True).returncode == 0
        if present:
            subprocess.run(["launchctl", "bootout", f"{domain}/{label}"], check=True)
        subprocess.run(["launchctl", "bootstrap", domain, str(plist)], check=True)
        print(f"Installed {label}: {calendar}")


if __name__ == "__main__":
    main()
