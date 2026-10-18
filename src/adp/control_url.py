"""Origin validation shared by human and worker control clients."""
from urllib.parse import urlsplit


def control_origin(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Control URL must contain only an origin")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid control URL port") from exc
    if (not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")
            or not parsed.netloc or port == 0):
        raise ValueError("Control URL must contain only an origin")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}):
        raise ValueError("Remote control plane requires HTTPS")
    return f"{parsed.scheme}://{parsed.netloc}"
