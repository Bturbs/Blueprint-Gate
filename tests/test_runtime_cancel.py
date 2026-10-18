import asyncio
import sys

import pytest

from adp.runtimes import _run


@pytest.mark.asyncio
async def test_cancel_sends_graceful_signal_to_cli(tmp_path):
    marker = tmp_path / "signal.txt"
    script = (
        "import signal,sys,time\n"
        "from pathlib import Path\n"
        "marker=Path(sys.argv[1])\n"
        "def stop(*args):\n"
        "    marker.write_text('terminated')\n"
        "    sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "marker.write_text('started')\n"
        "while True: time.sleep(0.1)\n"
    )
    task = asyncio.create_task(_run([sys.executable, "-c", script, str(marker)], "", tmp_path, 30))
    async with asyncio.timeout(5):
        while not marker.exists():
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    assert marker.read_text() == "terminated"
