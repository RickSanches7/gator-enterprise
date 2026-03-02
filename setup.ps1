#Requires -Version 5.1
<#
.SYNOPSIS
    GATOR PRO Enterprise v2.0 — Windows Setup Script (PowerShell)
.DESCRIPTION
    Проверяет зависимости, настраивает окружение, запускает Docker Compose.
    Запуск: Right-click → "Run with PowerShell"
    Или из консоли: powershell -ExecutionPolicy Bypass -File setup.ps1
#>

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "GATOR PRO Enterprise v2.0"

# ── Цвета ──────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host " ██████╗  █████╗ ████████╗ ██████╗ ██████╗ " -ForegroundColor Green
    Write-Host "██╔════╝ ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗" -ForegroundColor Green
    Write-Host "██║  ███╗███████║   ██║   ██║   ██║██████╔╝" -ForegroundColor Green
    Write-Host "██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗" -ForegroundColor Green
    Write-Host "╚██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║" -ForegroundColor Green
    Write-Host " ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝" -ForegroundColor Green
    Write-Host "         PRO ENTERPRISE v2.0 — Windows" -ForegroundColor Cyan
    Write-Host ""
}

function Write-OK   { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!]  $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "[X]  $msg" -ForegroundColor Red }
function Write-Info { param($msg) Write-Host "[*]  $msg" -ForegroundColor Cyan }

# ── Проверки ────────────────────────────────────────────────────
function Test-Requirements {
    Write-Info "Проверка требований..."

    # Docker Desktop
    try {
        $dockerVer = (docker --version 2>&1)
        Write-OK "Docker: $dockerVer"
    } catch {
        Write-Err "Docker Desktop не найден!"
        Write-Host ""
        Write-Host "  Установи Docker Desktop для Windows:" -ForegroundColor Yellow
        Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Требования системы:" -ForegroundColor Yellow
        Write-Host "  - Windows 10/11 64-bit (версия 1903+)" -ForegroundColor White
        Write-Host "  - WSL2 backend (рекомендуется)" -ForegroundColor White
        Write-Host "  - 8 GB RAM минимум (рекомендуется 16 GB)" -ForegroundColor White
        Write-Host "  - 10 GB свободного места на диске" -ForegroundColor White
        Write-Host "  - Virtualization включена в BIOS/UEFI" -ForegroundColor White
        Start-Process "https://www.docker.com/products/docker-desktop/"
        Read-Host "Нажми Enter после установки Docker Desktop"
        exit 1
    }

    # Docker Compose v2
    try {
        $composeVer = (docker compose version 2>&1)
        Write-OK "Docker Compose: $composeVer"
    } catch {
        Write-Err "Docker Compose v2 не найден! Обнови Docker Desktop."
        exit 1
    }

    # Docker запущен?
    try {
        docker info 2>&1 | Out-Null
        Write-OK "Docker Engine запущен"
    } catch {
        Write-Err "Docker Desktop не запущен!"
        Write-Host "  Запусти Docker Desktop из меню Пуск." -ForegroundColor Yellow
        Write-Host "  Дождись зелёной иконки в системном трее." -ForegroundColor Yellow
        Read-Host "Нажми Enter когда Docker запустится"

        # Повторная проверка
        Start-Sleep -Seconds 3
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Docker всё ещё не готов. Запусти скрипт снова."
            exit 1
        }
        Write-OK "Docker запущен"
    }

    # Место на диске
    $drive = (Get-Location).Drive.Name
    $freeGB = [math]::Round((Get-PSDrive $drive).Free / 1GB, 1)
    if ($freeGB -lt 8) {
        Write-Warn "Мало места на диске: ${freeGB} GB. Рекомендуется 10+ GB."
    } else {
        Write-OK "Свободное место: ${freeGB} GB"
    }

    # RAM
    $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    if ($ramGB -lt 8) {
        Write-Warn "RAM: ${ramGB} GB. GATOR PRO требует минимум 8 GB."
    } else {
        Write-OK "RAM: ${ramGB} GB"
    }

    # WSL2 (рекомендуется)
    try {
        $wslStatus = wsl --status 2>&1
        Write-OK "WSL2 доступен"
    } catch {
        Write-Warn "WSL2 не обнаружен. Docker работает медленнее без WSL2."
        Write-Host "  Установка WSL2: wsl --install" -ForegroundColor Gray
    }
}

# ── Настройка .env ──────────────────────────────────────────────
function Setup-Environment {
    Write-Host ""
    Write-Info "Настройка окружения..."

    if (-not (Test-Path ".env")) {
        Copy-Item ".env.example" ".env"

        # Генерация случайного SECRET_KEY
        $secretKey = -join ((65..90) + (97..122) + (48..57) |
            Get-Random -Count 64 | ForEach-Object { [char]$_ })

        # Замена в .env
        $envContent = Get-Content ".env" -Raw
        $envContent = $envContent -replace "change-this-to-a-random-64-char-string-in-production", $secretKey
        Set-Content ".env" $envContent -Encoding UTF8

        Write-OK ".env создан с уникальным секретным ключом"
        Write-Warn "Опционально: отредактируй .env для настройки:"
        Write-Host "  - TELEGRAM_BOT_TOKEN (уведомления в Telegram)" -ForegroundColor Gray
        Write-Host "  - NVD_API_KEY (быстрый CVE поиск, бесплатно)" -ForegroundColor Gray
        Write-Host "  - Пароли БД (если хочешь изменить)" -ForegroundColor Gray
    } else {
        Write-OK ".env уже существует"
    }
}

# ── Сборка образов ──────────────────────────────────────────────
function Build-Images {
    Write-Host ""
    Write-Info "Сборка Docker образов..."
    Write-Host "  Первый запуск: 5-15 минут (скачивается ~2 GB)" -ForegroundColor Gray
    Write-Host "  Последующие запуски: ~30 секунд" -ForegroundColor Gray
    Write-Host ""

    docker compose build
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Ошибка сборки Docker образов!"
        Write-Host "  Частые причины:" -ForegroundColor Yellow
        Write-Host "  - Нет интернета или firewall блокирует Docker" -ForegroundColor White
        Write-Host "  - Недостаточно места на диске" -ForegroundColor White
        Write-Host "  - Docker Desktop требует обновления" -ForegroundColor White
        exit 1
    }
    Write-OK "Образы собраны успешно"
}

# ── Запуск ──────────────────────────────────────────────────────
function Start-Services {
    Write-Host ""
    Write-Info "Запуск всех сервисов..."

    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Ошибка запуска сервисов!"
        Write-Host "  Логи:" -ForegroundColor Yellow
        docker compose logs --tail=40
        exit 1
    }

    Write-Info "Ожидаем готовности сервисов..."
    $timeout = 60
    $elapsed = 0

    while ($elapsed -lt $timeout) {
        Start-Sleep -Seconds 3
        $elapsed += 3
        $status = docker compose ps 2>&1
        if ($status -match "healthy") {
            break
        }
        Write-Host "  ... $elapsed сек" -ForegroundColor Gray
    }

    # Финальный статус
    Write-Host ""
    Write-Info "Статус сервисов:"
    docker compose ps
}

# ── Итог ────────────────────────────────────────────────────────
function Show-Success {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║         GATOR PRO ENTERPRISE — ЗАПУЩЕН!                 ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Открой в браузере:                                      ║" -ForegroundColor Green
    Write-Host "║                                                          ║" -ForegroundColor Green
    Write-Host "║  🌐 Интерфейс:   http://localhost:8080                  ║" -ForegroundColor Cyan
    Write-Host "║  ⚡ API:          http://localhost:8000                  ║" -ForegroundColor Cyan
    Write-Host "║  📚 API Docs:     http://localhost:8000/api/docs        ║" -ForegroundColor Cyan
    Write-Host "║  🌸 Celery UI:    http://localhost:5555                  ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Логин:   admin                                          ║" -ForegroundColor White
    Write-Host "║  Пароль:  GatorAdmin2024!                                ║" -ForegroundColor Yellow
    Write-Host "║  ⚠  СМЕНИ ПАРОЛЬ после первого входа!                   ║" -ForegroundColor Red
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Полезные команды (запускай в папке проекта):            ║" -ForegroundColor Green
    Write-Host "║    Стоп:    docker compose down                          ║" -ForegroundColor Gray
    Write-Host "║    Логи:    docker compose logs -f backend               ║" -ForegroundColor Gray
    Write-Host "║    Рестарт: docker compose restart                       ║" -ForegroundColor Gray
    Write-Host "║    Shell:   docker compose exec backend bash             ║" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
}

# ── MAIN ────────────────────────────────────────────────────────
Clear-Host
Write-Banner

# Перейти в папку скрипта
Set-Location $PSScriptRoot

try {
    Test-Requirements
    Setup-Environment
    Build-Images
    Start-Services
    Show-Success

    # Открыть браузер
    Write-Info "Открываем браузер..."
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:8080"

} catch {
    Write-Host ""
    Write-Err "Критическая ошибка: $_"
    Write-Host ""
    Write-Host "  Для помощи:" -ForegroundColor Yellow
    Write-Host "  - Email: GatorSupport@ya.ru" -ForegroundColor White
    Write-Host "  - Приложи вывод этого окна к письму" -ForegroundColor White
}

Write-Host ""
Read-Host "Нажми Enter для выхода"
