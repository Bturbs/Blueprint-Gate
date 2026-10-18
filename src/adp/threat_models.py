"""Adapter for corda/threat-model-tool's actual verifier CLI."""
import asyncio
import hashlib
import os
import signal
from pathlib import Path
import yaml


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


async def verify(root_model: Path, tool_root: Path, timeout: int = 120) -> dict:
    if not root_model.is_file():
        return {"passed": False, "error": "Root model not found"}
    script = tool_root / "src/scripts/verify-threat-model.ts"
    if not script.is_file():
        return {"passed": False, "error": "Threat model verifier not installed"}
    process = await asyncio.create_subprocess_exec(
        "npx", "--no-install", "tsx", str(script), str(root_model.resolve()),
        cwd=tool_root, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
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
    digest = hashlib.sha256()
    for model in sorted(root_model.parent.rglob("*.yaml")):
        digest.update(str(model.relative_to(root_model.parent)).encode())
        digest.update(model.read_bytes())
    return {
        "passed": process.returncode == 0,
        "root": str(root_model),
        "revision": digest.hexdigest(),
        "stdout": out.decode(errors="replace")[-4000:],
        "stderr": err.decode(errors="replace")[-4000:],
    }
