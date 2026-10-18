"""Provider-independent CLI execution. No provider credentials enter the control plane."""
import asyncio
import json
import os
import signal
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class RuntimeResult:
    provider: str
    status: str
    output: str
    usage: dict
    error: str | None = None


class AgentRuntime(Protocol):
    name: str

    async def validate_environment(self) -> dict: ...
    async def execute(self, prompt: str, cwd: Path, timeout: int = 900, writable: bool = False) -> RuntimeResult: ...
    async def cancel(self, execution_id: str) -> None: ...
    def get_capabilities(self) -> set[str]: ...
    async def get_usage_status(self) -> dict: ...


async def _run(argv: list[str], prompt: str, cwd: Path, timeout: int) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(prompt.encode()), timeout)
    except asyncio.TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.communicate()
        return 124, "", "execution timeout"
    except asyncio.CancelledError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.communicate()
        raise
    return process.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


class CodexCLIRuntime:
    name = "codex"

    async def validate_environment(self) -> dict:
        executable = shutil.which("codex")
        if not executable:
            return {"available": False, "reason": "codex CLI not installed"}
        rc, out, err = await _run(["codex", "login", "status"], "", Path.cwd(), 10)
        status = out + err
        return {"available": rc == 0 and "ChatGPT" in status, "auth": "ChatGPT" if "ChatGPT" in status else "not subscription-authenticated"}

    def get_capabilities(self) -> set[str]:
        return {"read", "edit", "structured_output"}

    async def get_usage_status(self) -> dict:
        return {"available": False, "reason": "CLI does not expose a stable usage endpoint"}

    async def cancel(self, execution_id: str) -> None:
        raise NotImplementedError("Cancellation is enforced by process timeout")

    async def execute(self, prompt: str, cwd: Path, timeout: int = 900, writable: bool = False) -> RuntimeResult:
        if not shutil.which("codex"):
            return RuntimeResult(self.name, "unavailable", "", {}, "codex CLI not installed")
        args = ["codex", "exec", "--json", "--sandbox", "workspace-write" if writable else "read-only", "-C", str(cwd), "-"]
        rc, out, err = await _run(args, prompt, cwd, timeout)
        events = []
        for line in out.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        last = next((e.get("item", {}).get("text", "") for e in reversed(events) if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "agent_message"), "")
        usage = next((e.get("usage", {}) for e in reversed(events) if e.get("type") == "turn.completed"), {})
        event_error = next((e.get("message", "") for e in reversed(events) if e.get("type") in {"error", "turn.failed"}), "")
        return RuntimeResult(self.name, "succeeded" if rc == 0 else "failed", last, usage, (err or event_error)[-2000:] if rc else None)


class ClaudeCodeRuntime:
    name = "claude"

    async def validate_environment(self) -> dict:
        executable = shutil.which("claude")
        if not executable:
            return {"available": False, "reason": "claude CLI not installed"}
        rc, out, _ = await _run(["claude", "auth", "status"], "", Path.cwd(), 10)
        try:
            method = json.loads(out).get("authMethod")
        except json.JSONDecodeError:
            method = None
        return {"available": rc == 0 and method in {"claude.ai", "oauth_token"}, "auth_method": method or "not authenticated"}

    def get_capabilities(self) -> set[str]:
        return {"read", "edit", "structured_output"}

    async def get_usage_status(self) -> dict:
        return {"available": False, "reason": "CLI usage status is not required for safe routing"}

    async def cancel(self, execution_id: str) -> None:
        raise NotImplementedError("Cancellation is enforced by process timeout")

    async def execute(self, prompt: str, cwd: Path, timeout: int = 900, writable: bool = False) -> RuntimeResult:
        if not shutil.which("claude"):
            return RuntimeResult(self.name, "unavailable", "", {}, "claude CLI not installed")
        args = ["claude", "-p", "--output-format", "json", "--permission-mode", "acceptEdits" if writable else "plan", prompt]
        rc, out, err = await _run(args, "", cwd, timeout)
        try:
            payload = json.loads(out)
            result = payload.get("result", "")
            usage = payload.get("usage", {})
            failed = bool(payload.get("is_error"))
        except json.JSONDecodeError:
            result, usage, failed = "", {}, True
        return RuntimeResult(self.name, "succeeded" if rc == 0 and not failed else "failed", result, usage, (err or str(result))[-2000:] if rc or failed else None)


RUNTIMES: dict[str, AgentRuntime] = {"codex": CodexCLIRuntime(), "claude": ClaudeCodeRuntime()}


def select_runtime(policy: dict, stage: str) -> AgentRuntime:
    return candidate_runtimes(policy, stage)[0]


def candidate_runtimes(policy: dict, stage: str) -> list[AgentRuntime]:
    routing = policy.get("routing", {})
    name = routing.get("roles", {}).get(stage, routing.get("default_provider", "codex"))
    allowed = routing.get("allowed_providers", ["codex"])
    if name not in allowed or name not in RUNTIMES:
        raise ValueError(f"Provider {name} is not allowed for this repository")
    classification = policy.get("data_classification", "internal")
    classifications = routing.get("provider_classifications", {})
    def authorized(provider: str) -> bool:
        return provider in allowed and provider in RUNTIMES and classification in classifications.get(provider, ["public", "internal"])
    if not authorized(name):
        raise ValueError(f"Provider {name} is not approved for {classification} data")
    candidates = [name]
    fallback = routing.get("fallback", {})
    if fallback.get("enabled"):
        candidates.extend(x for x in fallback.get("order", []) if x != name and authorized(x))
    return [RUNTIMES[x] for x in candidates]
