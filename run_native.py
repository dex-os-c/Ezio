#!/usr/bin/env python3
"""
run_native.py — Run Ezio WITHOUT Docker.

Replaces docker-compose.yml with plain local processes:
  - PostgreSQL   (you install/run this yourself — see NATIVE_SETUP.md)
  - Tor          (this script launches it if a `tor` binary is on PATH
                   and nothing is already listening on TOR_PROXY_PORT)
  - FastAPI      (uvicorn, run directly from your venv)
  - Next.js      (npm run build && npm run start, or --dev for `next dev`)

Same UI, same API, same ports (8000 backend / 3000 frontend) as the
Docker setup — just no Docker Desktop VM overhead and no images to
build. Safe to re-run; it re-uses whatever is already installed/running.

Usage:
    python run_native.py            # first run: sets up venv + npm deps, then starts everything
    python run_native.py --dev      # frontend in `next dev` mode instead of build+start
    python run_native.py --no-seed  # skip the (slow, optional) historical seed import
    python run_native.py --no-tor   # don't try to manage Tor yourself (use system Tor / Tor Browser)

Ctrl+C stops every process this script started (backend, frontend, and
Tor if it launched Tor). It never touches a Postgres or Tor instance
you started yourself outside this script.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
WEB_DIR = REPO_ROOT / "web"
VENV_DIR = REPO_ROOT / ".venv"
IS_WINDOWS = platform.system() == "Windows"

CHILD_PROCESSES: list[subprocess.Popen] = []


# ---------------------------------------------------------------- helpers --

def log(msg: str) -> None:
    print(f"[ezio-native] {msg}", flush=True)


def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def load_env_file(path: Path) -> dict:
    """Minimal .env parser — no dependency on python-dotenv being installed yet."""
    env = dict(os.environ)
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        env.setdefault(key, value)
        env[key] = env.get(key) or value
        if key not in os.environ:
            env[key] = value
    return env


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    log("→ " + " ".join(str(c) for c in cmd))
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def spawn(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.Popen:
    log("→ (background) " + " ".join(str(c) for c in cmd))
    kwargs = {}
    if not IS_WINDOWS:
        kwargs["preexec_fn"] = os.setsid  # own process group, so we can kill children too
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, **kwargs)
    CHILD_PROCESSES.append(proc)
    return proc


def stop_all(*_):
    log("shutting down...")
    for proc in reversed(CHILD_PROCESSES):
        if proc.poll() is not None:
            continue
        try:
            if IS_WINDOWS:
                proc.terminate()
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(1)
    for proc in CHILD_PROCESSES:
        if proc.poll() is None:
            proc.kill()
    sys.exit(0)


# ---------------------------------------------------------- setup / prereqs --

def ensure_venv() -> Path:
    py = venv_python()
    if not py.exists():
        log("creating Python venv in .venv/ (first run only)...")
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
        run([str(py), "-m", "pip", "install", "--upgrade", "pip"])
        log("installing Python dependencies (base install — no torch/chromadb/playwright)...")
        run([str(py), "-m", "pip", "install", "-e", "."])
        log("downloading spaCy English model...")
        run([str(py), "-m", "spacy", "download", "en_core_web_sm"])
    return py


def ensure_npm_deps() -> None:
    if not (WEB_DIR / "node_modules").exists():
        npm = "npm.cmd" if IS_WINDOWS else "npm"
        if not shutil.which(npm):
            sys.exit(
                "Node.js/npm not found on PATH. Install Node 18+ first — see NATIVE_SETUP.md."
            )
        log("installing frontend dependencies (first run only)...")
        run([npm, "install"], cwd=WEB_DIR)


def check_postgres(env: dict) -> None:
    db_url = env.get("DATABASE_URL", "")
    if not db_url:
        sys.exit("DATABASE_URL is not set. Copy .env.native.example to .env and edit it.")
    parsed = urllib.parse.urlparse(db_url)
    host, port = parsed.hostname or "localhost", parsed.port or 5432
    if not port_open(host, port):
        sys.exit(
            f"Cannot reach PostgreSQL at {host}:{port}.\n"
            "Install and start PostgreSQL locally first — see NATIVE_SETUP.md.\n"
            f"Then make sure DATABASE_URL in .env matches (currently: {db_url})"
        )
    log(f"PostgreSQL reachable at {host}:{port}")


def ensure_tor(env: dict, manage_tor: bool) -> None:
    host = env.get("TOR_PROXY_HOST", "127.0.0.1")
    port = int(env.get("TOR_PROXY_PORT", "9050"))
    if port_open(host, port):
        log(f"Tor already reachable at {host}:{port} (using it as-is)")
        return
    if not manage_tor:
        log(f"WARNING: nothing listening on {host}:{port} and --no-tor was passed — "
            "dark-web crawling/search features will fail until Tor is running.")
        return
    tor_bin = shutil.which("tor")
    if not tor_bin:
        log("WARNING: no `tor` binary on PATH and nothing listening on "
            f"{host}:{port}. Install Tor (see NATIVE_SETUP.md) or start Tor "
            "Browser, or pass --no-tor to suppress this warning.")
        return
    log("starting local Tor process (SocksPort 9050 + 9250 isolated)...")
    tor_data_dir = REPO_ROOT / ".native_run" / "tor-data"
    tor_data_dir.mkdir(parents=True, exist_ok=True)
    spawn([
        tor_bin,
        "--SocksPort", "127.0.0.1:9050",
        "--SocksPort", "127.0.0.1:9250 IsolateDestAddr IsolateDestPort",
        "--DataDirectory", str(tor_data_dir),
    ])
    for _ in range(30):
        if port_open(host, port):
            log("Tor is up.")
            return
        time.sleep(1)
    log("WARNING: Tor did not come up within 30s — check .native_run/tor-data for logs.")


def run_migrations(py: Path, env: dict) -> None:
    log("applying database migrations...")
    run([str(py), "-m", "alembic", "upgrade", "head"], cwd=REPO_ROOT, env=env)


def maybe_import_seed(py: Path, env: dict, skip: bool) -> None:
    if skip:
        log("skipping seed data import (--no-seed)")
        return
    seed_gz = REPO_ROOT / "data" / "seed_data.json.gz"
    if not seed_gz.exists():
        log("no local seed bundle found — attempting download (non-fatal if it fails)...")
        try:
            run([str(py), "scripts/download_seed.py"], cwd=REPO_ROOT, env=env)
        except subprocess.CalledProcessError:
            log("seed download failed/skipped — continuing without it.")
            return
    log("importing seed data in background (idempotent, safe to skip with --no-seed)...")
    # import_seed.py hardcodes a Docker path (/data/seed_data.json.gz); point it at
    # the repo-relative file instead without touching the original script.
    patch = (
        "import sys; sys.path.insert(0, '.'); "
        "import scripts.import_seed as m; "
        "m.SEED_FILE = 'data/seed_data.json.gz'; "
        "m.main()"
    )
    spawn([str(py), "-c", patch], cwd=REPO_ROOT, env=env)


def start_backend(py: Path, env: dict) -> None:
    log("starting FastAPI backend on http://localhost:8000 ...")
    spawn(
        [str(py), "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=REPO_ROOT,
        env=env,
    )


def start_frontend(env: dict, dev: bool) -> None:
    npm = "npm.cmd" if IS_WINDOWS else "npm"
    fe_env = dict(env)
    fe_env.setdefault("NEXT_PUBLIC_API_URL", "http://localhost:8000")
    if dev:
        log("starting Next.js in dev mode on http://localhost:3000 ...")
        spawn([npm, "run", "dev"], cwd=WEB_DIR, env=fe_env)
        return
    if not (WEB_DIR / ".next").exists():
        log("building frontend for production (first run only, one-time cost)...")
        run([npm, "run", "build"], cwd=WEB_DIR, env=fe_env)
    log("starting Next.js on http://localhost:3000 ...")
    spawn([npm, "run", "start"], cwd=WEB_DIR, env=fe_env)


# ------------------------------------------------------------------- main --

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--dev", action="store_true", help="run frontend with `next dev` instead of build+start")
    parser.add_argument("--no-seed", action="store_true", help="skip historical seed data import")
    parser.add_argument("--no-tor", action="store_true", help="don't launch/manage Tor yourself")
    args = parser.parse_args()

    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        example = REPO_ROOT / ".env.native.example"
        sys.exit(
            f".env not found. Copy {example.name} to .env, fill in DATABASE_URL "
            "(and a JWT_SECRET), then re-run."
        )
    env = load_env_file(env_file)
    env.setdefault("TOR_PROXY_HOST", "127.0.0.1")
    env.setdefault("TOR_PROXY_PORT", "9050")

    signal.signal(signal.SIGINT, stop_all)
    signal.signal(signal.SIGTERM, stop_all)

    py = ensure_venv()
    ensure_npm_deps()
    check_postgres(env)
    ensure_tor(env, manage_tor=not args.no_tor)
    run_migrations(py, env)
    maybe_import_seed(py, env, skip=args.no_seed)
    start_backend(py, env)
    time.sleep(2)
    start_frontend(env, dev=args.dev)

    log("")
    log("Ezio is running:")
    log("  Frontend:  http://localhost:3000")
    log("  API docs:  http://localhost:8000/docs")
    log("Press Ctrl+C to stop everything.")
    log("")

    while True:
        time.sleep(1)
        for proc in CHILD_PROCESSES:
            if proc.poll() not in (None,) and proc.args and "uvicorn" in " ".join(map(str, proc.args)):
                log("backend process exited unexpectedly — stopping.")
                stop_all()


if __name__ == "__main__":
    main()
