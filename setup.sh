#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GATOR PRO ENTERPRISE v2.0 — One-Click Setup & Launch
# gator.uz | GatorSupport@ya.ru
# ═══════════════════════════════════════════════════════════════
# Usage: bash setup.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${GREEN}"
  cat << 'EOF'
  ██████╗  █████╗ ████████╗ ██████╗ ██████╗
 ██╔════╝ ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
 ██║  ███╗███████║   ██║   ██║   ██║██████╔╝
 ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
 ╚██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
       PRO ENTERPRISE v2.0 — gator.uz
EOF
  echo -e "${NC}"
}

check_requirements() {
  echo -e "${CYAN}[*] Checking requirements...${NC}"

  if ! command -v docker &>/dev/null; then
    echo -e "${RED}[✗] Docker not found!${NC}"
    echo "    Install: https://docs.docker.com/engine/install/"
    exit 1
  fi
  echo -e "${GREEN}[✓] Docker $(docker --version | cut -d' ' -f3 | tr -d ',')${NC}"

  if ! docker compose version &>/dev/null 2>&1; then
    echo -e "${RED}[✗] Docker Compose v2 not found!${NC}"
    echo "    Install: https://docs.docker.com/compose/install/"
    exit 1
  fi
  echo -e "${GREEN}[✓] Docker Compose $(docker compose version --short)${NC}"
}

setup_env() {
  echo -e "\n${CYAN}[*] Setting up environment...${NC}"
  if [ ! -f ".env" ]; then
    cp .env.example .env
    # Generate random secret key
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    sed -i "s/change-this-to-a-random-64-char-string-in-production/$SECRET/" .env
    echo -e "${GREEN}[✓] .env created with random secret key${NC}"
    echo -e "${YELLOW}[!] Edit .env to set TELEGRAM_BOT_TOKEN and NVD_API_KEY (optional)${NC}"
  else
    echo -e "${GREEN}[✓] .env already exists${NC}"
  fi
}

build_and_start() {
  echo -e "\n${CYAN}[*] Building Docker images (first time: ~5-10 min)...${NC}"
  docker compose build --parallel

  echo -e "\n${CYAN}[*] Starting services...${NC}"
  docker compose up -d

  echo -e "\n${CYAN}[*] Waiting for services to be healthy...${NC}"
  local attempts=0
  while [ $attempts -lt 30 ]; do
    if docker compose ps | grep -q "healthy"; then
      break
    fi
    sleep 3
    attempts=$((attempts + 1))
    echo -n "."
  done
  echo ""
}

show_status() {
  echo -e "\n${CYAN}[*] Service status:${NC}"
  docker compose ps

  echo -e "\n${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║          GATOR PRO ENTERPRISE — RUNNING              ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  🌐 Frontend UI:  http://localhost:8080              ║${NC}"
  echo -e "${GREEN}║  ⚡ Backend API:  http://localhost:8000              ║${NC}"
  echo -e "${GREEN}║  📚 API Docs:     http://localhost:8000/api/docs     ║${NC}"
  echo -e "${GREEN}║  🌸 Celery UI:    http://localhost:5555              ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  Default login:  admin / GatorAdmin2024!             ║${NC}"
  echo -e "${YELLOW}║  ⚠  CHANGE PASSWORD after first login!               ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  Logs:   docker compose logs -f backend              ║${NC}"
  echo -e "${GREEN}║  Stop:   docker compose down                         ║${NC}"
  echo -e "${GREEN}║  Shell:  docker compose exec backend bash            ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
}

# ── MAIN ──────────────────────────────────────────────────────
clear
banner
check_requirements
setup_env
build_and_start
show_status
