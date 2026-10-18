"""Adapter for corda/threat-model-tool's actual verifier CLI."""
import asyncio
import hashlib
import os
import signal
import subprocess
from pathlib import Path
import yaml

from adp.process_env import UntrustedSandbox, child_environment, untrusted_argv


def discover(root: Path) -> list[Path]:
    """Only return conventionally named models; never manufacture a model."""
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*.yaml") if p.stem == p.parent.name)


def in_place_controls(root: Path) -> dict[str, bool]:
    """Read control status across a model tree for design-time evidence checks."""
    found: dict[str, bool] = {}
    if not root.exists():
        return found
    for path in root.rglob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        def walk(value):
            if isinstance(value, dict):
                for control in value.get("countermeasures", []) or []:
                    if isinstance(control, dict) and control.get("ID"):
                        found[f"{path.relative_to(root)}:{control['ID']}"] = control.get("inPlace") is True
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(data)
    return found


def reject_unverified_controls(before: dict[str, bool], after: dict[str, bool]) -> None:
    added = [key for key, value in after.items() if value and not before.get(key, False)]
    if added:
        raise ValueError(f"Design-stage model marked unverified controls in place: {', '.join(added)}")


def model_revision(root_model: Path) -> str:
    digest = hashlib.sha256()
    for model in sorted(root_model.parent.rglob("*.yaml")):
        digest.update(str(model.relative_to(root_model.parent)).encode())
        digest.update(model.read_bytes())
    return digest.hexdigest()


def committed_model_revision(repository: Path, model_directory: Path, commit_sha: str) -> str:
    """Hash the immutable Git tree using the same relative YAML paths as verify()."""
    prefix = model_directory.resolve().relative_to(repository.resolve())
    listing = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "-z", "--name-only", commit_sha, "--", str(prefix)],
        check=True, capture_output=True,
    ).stdout
    digest = hashlib.sha256()
    for raw_path in sorted(path for path in listing.split(b"\0") if path.endswith(b".yaml")):
        repo_path = raw_path.decode()
        relative = str(Path(repo_path).relative_to(prefix))
        contents = subprocess.run(
            ["git", "-C", str(repository), "show", f"{commit_sha}:{repo_path}"],
            check=True, capture_output=True,
        ).stdout
        digest.update(relative.encode())
        digest.update(contents)
    return digest.hexdigest()


async def verify(root_model: Path, tool_root: Path, timeout: int = 120, untrusted_user: str | None = None,
                 sandbox: UntrustedSandbox | None = None) -> dict:
    if not root_model.is_file():
        return {"passed": False, "error": "Root model not found"}
    script = tool_root / "src/scripts/verify-threat-model.ts"
    if not script.is_file():
        return {"passed": False, "error": "Threat model verifier not installed"}
    argv = ["npx", "--no-install", "tsx", str(script), str(root_model.resolve())]
    env = child_environment("verify")
    if untrusted_user:
        if sandbox:
            argv, env = untrusted_argv(argv, untrusted_user, "verify", sandbox=sandbox)
        else:
            argv, env = untrusted_argv(argv, untrusted_user, "verify")
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=tool_root, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True, env=env,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.communicate()
        return {"passed": False, "error": "Verification timeout"}
    except asyncio.CancelledError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.communicate()
        raise
    return {
        "passed": process.returncode == 0,
        "root": str(root_model),
        "revision": model_revision(root_model),
        "stdout": out.decode(errors="replace")[-4000:],
        "stderr": err.decode(errors="replace")[-4000:],
    }
