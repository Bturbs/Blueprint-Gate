import asyncio
import json
import shutil
import time
from pathlib import Path

import httpx
import typer

from adp.runtimes import RUNTIMES
from adp.worker import run_worker

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
    """Run a local worker against a local or remote control plane."""
    asyncio.run(run_worker(config, once))


@app.command()
def poll(control_url: str, token: str, repository_id: str):
    """Poll a configured GitHub repository once."""
    with httpx.Client(base_url=control_url, headers={"Authorization": f"Bearer {token}"}) as client:
        response = client.post(f"/repositories/{repository_id}/poll", timeout=60)
        response.raise_for_status()
        typer.echo(json.dumps(response.json(), indent=2))


@app.command()
def scheduler(control_url: str, token: str, interval: int = 60):
    """Continuously reconcile GitHub issues and eligible merges."""
    with httpx.Client(base_url=control_url, headers={"Authorization": f"Bearer {token}"}, timeout=60) as client:
        while True:
            try:
                repos = client.get("/repositories")
                repos.raise_for_status()
                for repo in repos.json():
                    response = client.post(f"/repositories/{repo['id']}/poll")
                    response.raise_for_status()
                response = client.post("/reconcile-threat-reviews")
                response.raise_for_status()
                response = client.post("/reconcile-merges")
                response.raise_for_status()
                response = client.post("/reconcile-projects")
                response.raise_for_status()
            except httpx.HTTPError as exc:
                typer.echo(f"Reconciliation failed: {exc}", err=True)
            time.sleep(max(interval, 10))
