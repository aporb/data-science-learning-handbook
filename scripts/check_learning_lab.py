#!/usr/bin/env python3
"""Check the already-running synthetic learning lab without displaying its token.

Usage: HANDBOOK_NOTEBOOK_PORT=18888 python scripts/check_learning_lab.py
Start the fdsh-learning Compose project first. This script never starts the legacy stack.
"""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-p", "fdsh-learning", "-f", "compose.learning.yml", "--profile", "learning"]


def command(*args):
    return subprocess.check_output([*COMPOSE, *args], cwd=ROOT, text=True).strip()


def status(url, token=None):
    headers = {"Authorization": f"token {token}"} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=2) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def main():
    port = int(os.environ.get("HANDBOOK_NOTEBOOK_PORT", "8888"))
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 60
    while True:
        try:
            denied = status(base + "/api/contents")
            break
        except (OSError, TimeoutError):
            if time.monotonic() >= deadline:
                raise RuntimeError("Notebook did not become ready within 60 seconds") from None
            time.sleep(1)
    assert denied in (401, 403), f"Unauthenticated content access returned {denied}"
    # Capture only this lab's generated credential in memory. Never print it or put it in a URL.
    token = command("exec", "-T", "notebook", "python", "-c",
                    "import glob,json; p=glob.glob('/tmp/jupyter-runtime/jpserver-*.json'); "
                    "assert len(p)==1; print(json.load(open(p[0]))['token'])")
    assert token, "Notebook token is empty"
    allowed = status(base + "/api/contents", token)
    assert allowed == 200, f"Authenticated content access returned {allowed}"
    assert command("exec", "-T", "notebook", "id", "-u") == "1000"
    container = command("ps", "-q", "notebook")
    info = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    bindings = info["HostConfig"]["PortBindings"]
    assert all(binding["HostIp"] == "127.0.0.1" for rows in bindings.values() for binding in rows)
    chapters = next(mount for mount in info["Mounts"] if mount["Destination"].endswith("/chapters"))
    assert chapters["RW"] is False
    assert info["HostConfig"]["ReadonlyRootfs"] is True
    print(f"Learning lab: unauthenticated={denied}, authenticated={allowed}, UID=1000, loopback-only, read-only chapters/root")


if __name__ == "__main__":
    main()
