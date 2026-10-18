import asyncio
import json
import os
import shutil
import signal
import time
from pathlib import Path

import httpx
import typer

from adp.runtimes import RUNTIMES
from adp.worker import run_worker
from adp.control_url import control_origin

app = typer.Typer(help="Autonomous development platform operations")


@app.command()
def doctor():
    """Check local prerequisites without exposing credentials."""
    for binary in ("docker", "git", "gh", "node", "npx", "codex", "claude"):
        typer.echo(f"{binary}: {'found' if shutil.which(binary) else 'missing'}")
    for name, runtime in RUNTIMES.items():
        typer.echo(f"{name}: {json.dumps(asyncio.run(runtime.validate_environment()))}")


@app.command()
def worker(config: Path = typer.Option(Path("worker.yaml"), help="Local worker configuration"), once: bool = False):
    """Run a worker. Press Ctrl-C once to release its current job safely."""
    async def serve():
        loop = asyncio.get_running_loop()
        current = asyncio.current_task()
        previous = signal.getsignal(signal.SIGTERM)
        installed = False
        try:
            loop.add_signal_handler(signal.SIGTERM, current.cancel)
            installed = True
        except (NotImplementedError, RuntimeError):
            pass
        try:
            await run_worker(config, once)
        finally:
            if installed:
                loop.remove_signal_handler(signal.SIGTERM)
                signal.signal(signal.SIGTERM, previous)

    asyncio.run(serve())


def _control_client(control_url: str, token_env: str, *, allow_container_control: bool = False, timeout: float = 15) -> httpx.Client:
    try:
        origin = control_origin(control_url, allow_container_control=allow_container_control)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    token = os.environ.get(token_env)
    if not token:
        raise typer.BadParameter(f"Set {token_env} in the environment")
    headers = {"Authorization": f"Bearer {token}"}
    human_token = os.environ.get("ADP_HUMAN_GITHUB_TOKEN")
    if human_token:
        headers["X-Human-Authorization"] = f"Bearer {human_token}"
    return httpx.Client(base_url=origin, headers=headers, timeout=timeout)


def _control_path(repository_id: str | None) -> str:
    return f"/repositories/{repository_id}/control" if repository_id else "/control"


@app.command()
def pause(control_url: str, repository_id: str | None = typer.Option(None), token_env: str = typer.Option("CONTROL_TOKEN"), wait_seconds: int = typer.Option(30, min=0)):
    """Stop new claims and ask active workers to yield, then wait for drain."""
    path = _control_path(repository_id)
    with _control_client(control_url, token_env) as client:
        response = client.post(f"{path}/pause")
        response.raise_for_status()
        state = response.json()
        deadline = time.monotonic() + wait_seconds
        while state.get("running_jobs", 0) and time.monotonic() < deadline:
            time.sleep(1)
            response = client.get(path)
            response.raise_for_status()
            state = response.json()
    typer.echo(json.dumps(state))
    if state.get("running_jobs", 0):
        typer.echo("Pause requested, but active jobs remain. Wait for workers to yield; a lost worker can be reclaimed after its lease expires and dispatch resumes.", err=True)
        raise typer.Exit(2)


@app.command()
def resume(control_url: str, repository_id: str | None = typer.Option(None), token_env: str = typer.Option("CONTROL_TOKEN")):
    """Allow queued jobs to be claimed again."""
    path = _control_path(repository_id)
    with _control_client(control_url, token_env) as client:
        response = client.post(f"{path}/resume")
        response.raise_for_status()
        typer.echo(json.dumps(response.json()))


@app.command("control-status")
def control_status(control_url: str, repository_id: str | None = typer.Option(None), token_env: str = typer.Option("CONTROL_TOKEN")):
    """Show whether dispatch is paused and how many jobs are still running."""
    with _control_client(control_url, token_env) as client:
        response = client.get(_control_path(repository_id))
        response.raise_for_status()
        typer.echo(json.dumps(response.json()))


@app.command()
def poll(control_url: str, repository_id: str, token_env: str = typer.Option("CONTROL_TOKEN")):
    """Poll a configured GitHub repository once."""
    with _control_client(control_url, token_env) as client:
        response = client.post(f"/repositories/{repository_id}/poll", timeout=60)
        response.raise_for_status()
        typer.echo(json.dumps(response.json(), indent=2))


@app.command()
def scheduler(control_url: str, interval: int = 60, token_env: str = typer.Option("CONTROL_TOKEN")):
    """Continuously reconcile GitHub issues and eligible merges."""
    with _control_client(control_url, token_env, allow_container_control=True, timeout=60) as client:
        while True:
            try:
                repos = client.get("/repositories")
                repos.raise_for_status()
                for repo in repos.json():
                    response = client.post(f"/repositories/{repo['id']}/poll")
                    response.raise_for_status()
                response = client.post("/reconcile-threat-reviews")
                response.raise_for_status()
                response = client.post("/reconcile-publications")
                response.raise_for_status()
                response = client.post("/reconcile-merges")
                response.raise_for_status()
                response = client.post("/reconcile-projects")
                response.raise_for_status()
            except httpx.HTTPError as exc:
                typer.echo(f"Reconciliation failed: {exc}", err=True)
            time.sleep(max(interval, 10))
