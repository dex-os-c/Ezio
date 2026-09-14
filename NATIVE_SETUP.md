# Running Ezio without Docker

This replaces the whole `docker-compose.yml` stack (Postgres + Tor + FastAPI +
Next.js containers) with plain local processes, managed by one script:
`run_native.py`. Same UI, same API, same ports (`localhost:3000` frontend,
`localhost:8000` backend) — you're just no longer paying for Docker Desktop's
VM overhead, which is the actual "potato PC can't run it" problem, not the
app itself.

You install three things once (Python, Node, PostgreSQL, Tor). After that,
`python run_native.py` does everything else: creates a venv, installs
dependencies, runs migrations, and starts the backend + frontend.

## 1. Install prerequisites

You need: **Python 3.11+**, **Node.js 18+**, **PostgreSQL 14+**, and **Tor**
(Tor is optional but required for the actual dark-web crawling features —
the UI and everything else works without it).

### Windows

- Python: https://www.python.org/downloads/ — check "Add python.exe to PATH" during install.
- Node.js: https://nodejs.org/ (LTS installer).
- PostgreSQL: https://www.postgresql.org/download/windows/ — the installer sets up the service for you and lets you set a password for the `postgres` user during setup.
- Tor: download the "Expert Bundle" from https://www.torproject.org/download/tor/, unzip it, and add the folder containing `tor.exe` to your PATH. (Or just run Tor Browser in the background — it also opens a SOCKS port.)

### macOS (Homebrew)

```bash
brew install python@3.11 node postgresql@16 tor
brew services start postgresql@16
brew services start tor
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm postgresql tor
sudo systemctl enable --now postgresql
sudo systemctl enable --now tor
```

(If your distro's `nodejs` package is older than 18, use https://github.com/nvm-sh/nvm instead.)

## 2. Create the Ezio database

Once PostgreSQL is running, create a user and database matching what you'll
put in `.env` (defaults below use user `ezio`, database `ezio`):

```bash
# Linux/Mac
sudo -u postgres psql -c "CREATE USER ezio WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "CREATE DATABASE ezio OWNER ezio;"
```

On Windows, use pgAdmin (installed alongside PostgreSQL) or `psql` from the
Start Menu to run the same two `CREATE` statements.

## 3. Configure

```bash
cp .env.native.example .env
```

Edit `.env`:
- `DATABASE_URL=postgresql://ezio:changeme@localhost:5432/ezio` (match what you created above)
- `JWT_SECRET=` — generate one: `python -c "import secrets; print(secrets.token_hex(32))"`
- Everything else (LLM API keys, enrichment source keys, etc.) is optional — leave blank to disable that feature.

## 4. Run

```bash
python run_native.py
```

First run will take a few minutes (creates a Python venv, installs
dependencies, installs frontend packages, builds the frontend). Every run
after that is fast. When it's up:

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

Press `Ctrl+C` to stop everything the script started.

### Useful flags

```bash
python run_native.py --dev       # frontend in `next dev` mode (faster iteration, more RAM)
python run_native.py --no-seed   # skip the optional historical seed-data import
python run_native.py --no-tor    # you're managing Tor yourself (system service / Tor Browser)
```

## What got lighter, concretely

- No Docker Desktop VM (saves ~2-4GB of RAM baseline on Windows/Mac before Ezio even starts).
- No image builds/layers — dependencies install directly into `.venv/` and `web/node_modules/`.
- Base Python install skips `torch`, `chromadb`, and `playwright` entirely (these were already optional extras in `pyproject.toml`, just bundled by default in the Docker image). If you need embeddings/vector search/JS-rendering later: `.venv/bin/pip install -e ".[nlp,vector,js]"`.
- Postgres and Tor run as normal lightweight OS processes/services instead of containers.

## Troubleshooting

- **"Cannot reach PostgreSQL"** — check the service is running (`sudo systemctl status postgresql` / Windows Services panel / `brew services list`) and that `DATABASE_URL` matches the user/password/database you created.
- **Tor warning on startup** — dark-web search/crawling needs Tor; everything else in the UI still works without it.
- **Frontend won't start / stale build** — delete `web/.next` and re-run.
- **Start over from scratch** — delete `.venv/` and `web/node_modules/`, re-run `python run_native.py`.
