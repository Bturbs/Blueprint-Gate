"""Give each worker subprocess only the environment it needs."""

import os
import pwd
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


_BASE = {
    "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "COLORTERM",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "VIRTUAL_ENV", "CI", "NO_COLOR", "PYTHONIOENCODING",
}
_PROVIDER = {
    "codex": {"CODEX_HOME"},
    "claude": {"CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN"},
}
_DELIVERY = {
    "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_CONFIG_DIR",
}
_GIT_LOCAL = {
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL", "GPG_TTY",
}
_GIT_PUSH = _GIT_LOCAL | {
    "SSH_AUTH_SOCK", "GIT_TERMINAL_PROMPT", "GIT_SSH", "GIT_SSH_COMMAND",
    "GIT_ASKPASS", "SSH_ASKPASS", "DISPLAY",
}
_PROXIES = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
_VM_WORKSPACE = Path("/srv/blueprint-gate")


@dataclass(frozen=True)
class UntrustedSandbox:
    """Filesystem view for one untrusted job inside the dedicated Linux VM."""

    workdir: Path
    writable: tuple[Path, ...] = ()
    readonly: tuple[Path, ...] = ()
    root: Path = _VM_WORKSPACE
    network: bool = True


def _sandbox_argv(argv: list[str], home: Path, sandbox: UntrustedSandbox) -> list[str]:
    if not shutil.which("bwrap"):
        raise ValueError("Filesystem confinement requires bubblewrap")
    root = sandbox.root.resolve(strict=True)
    if root != _VM_WORKSPACE or not root.is_dir():
        raise ValueError("Filesystem confinement requires the trusted VM workspace")
    workdir = sandbox.workdir.resolve(strict=True)
    writable = tuple(path.resolve(strict=True) for path in sandbox.writable)
    readonly = tuple(path.resolve(strict=True) for path in sandbox.readonly)
    for path in (*writable, *readonly):
        if not path.is_relative_to(root) or path == root:
            raise ValueError("Sandbox path escapes the trusted VM workspace")
    if workdir not in writable and workdir not in readonly:
        raise ValueError("Sandbox workdir is not an allowed path")
    if any(left == right or left.is_relative_to(right) or right.is_relative_to(left)
           for left in writable for right in readonly):
        raise ValueError("Sandbox writable and read-only paths overlap")
    command = [
        "bwrap", "--ro-bind", "/", "/", "--tmpfs", "/home",
        "--bind", str(home), str(home),
        "--tmpfs", str(root), "--tmpfs", "/tmp", "--proc", "/proc",
        "--dev", "/dev", "--unshare-pid", "--die-with-parent",
    ]
    if not sandbox.network:
        command.append("--unshare-net")
    for path in readonly:
        command.extend(("--ro-bind", str(path), str(path)))
    for path in writable:
        command.extend(("--bind", str(path), str(path)))
    command.extend(("--chdir", str(workdir), "--", *argv))
    return command


def child_environment(purpose: str, provider: str | None = None) -> dict[str, str]:
    """Build a purpose-specific allowlist without copying service credentials.

    This limits inherited environment exposure. It does not isolate files or
    network access; untrusted work still needs a confined worker host.
    """
    if purpose == "runtime":
        allowed = _BASE | _PROVIDER.get(provider or "", set())
    elif purpose in {"check", "verify"}:
        allowed = _BASE
    elif purpose == "git_local":
        allowed = _BASE | _GIT_LOCAL
    elif purpose == "delivery":
        allowed = _BASE | _DELIVERY
    elif purpose == "git_push":
        allowed = _BASE | _GIT_PUSH
    else:
        raise ValueError(f"Unknown subprocess purpose: {purpose}")
    selected = {name: value for name, value in os.environ.items() if name in allowed}
    for name in _PROXIES & selected.keys():
        if name.lower() == "no_proxy":
            continue
        parsed = urlsplit(selected[name])
        if parsed.username or parsed.password:
            selected.pop(name)
    return selected


def untrusted_argv(argv: list[str], username: str, purpose: str, provider: str | None = None,
                   sandbox: UntrustedSandbox | None = None) -> tuple[list[str], dict[str, str]]:
    """Run checkout-driven tools as a separate Unix identity, with a fresh env.

    The worker account holds its claim and delivery credentials. The agent
    account owns only provider credentials and writable checkout content.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ValueError("Invalid untrusted worker username")
    account = pwd.getpwnam(username)
    if account.pw_uid == 0 or account.pw_uid == os.getuid():
        raise ValueError("Untrusted commands require a distinct non-root Unix identity")
    allowed = child_environment(purpose, provider)
    for key in ("HOME", "USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN", "VIRTUAL_ENV"):
        allowed.pop(key, None)
    allowed.update({"HOME": account.pw_dir, "USER": username, "LOGNAME": username})
    if provider == "codex":
        allowed["CODEX_HOME"] = f"{account.pw_dir}/.codex"
    elif provider == "claude":
        allowed["CLAUDE_CONFIG_DIR"] = f"{account.pw_dir}/.claude"
    if sandbox:
        allowed["GIT_OPTIONAL_LOCKS"] = "0"
    command = _sandbox_argv(argv, Path(account.pw_dir), sandbox) if sandbox else argv
    return ["sudo", "-n", "-u", username, "--", "env", "-i", *(f"{key}={value}" for key, value in allowed.items()), "sh", "-c", 'umask 002; exec "$@"', "sh", *command], child_environment("check")
