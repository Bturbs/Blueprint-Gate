"""Give each worker subprocess only the environment it needs."""

import os
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
