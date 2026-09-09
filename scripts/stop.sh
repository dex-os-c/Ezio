#!/usr/bin/env bash
# Ezio — stop the full stack.
# Usage: ./scripts/stop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

printf "\n"
printf "${CYAN}"
printf "  ╔═══════════════════════════════════╗\n"
printf "  ║  Ezio  ·  Shutting down     ║\n"
printf "  ╚═══════════════════════════════════╝\n"
printf "${NC}\n"

if ! docker info > /dev/null 2>&1; then
    if sudo docker info > /dev/null 2>&1; then
        printf "\n  ${YELLOW}⚠${NC}  Docker requires sudo on this system.\n"
        printf "  ${DIM}→${NC}  Re-run with: ${BOLD}sudo bash scripts/stop.sh${NC}\n\n"
        exit 1
    else
        printf "\n  ${RED}✗${NC}  Docker not found or not running.\n"
        printf "  ${DIM}→${NC}  Install: ${DIM}https://docs.docker.com/get-docker/${NC}\n\n"
        exit 1
    fi
fi

printf "  ${DIM}→${NC}  Stopping containers...\n"
ENV_ARG=""
if [ -f "$REPO_ROOT/.env" ]; then
    ENV_ARG="--env-file $REPO_ROOT/.env"
fi
docker compose -f "$REPO_ROOT/docker-compose.yml" \
    --project-directory "$REPO_ROOT" \
    $ENV_ARG \
    down > /dev/null 2>&1
printf "  ${GREEN}✓${NC}  All services stopped\n"
printf "\n"
