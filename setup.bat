@echo off
setlocal

echo.
echo  ========================================
echo   GATOR PRO Enterprise v2.0 - Setup
echo  ========================================
echo.

echo [*] Checking Docker...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker not found!
    echo         Install: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
docker --version
echo [OK] Docker found.

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Docker is not running!
    echo         Start Docker Desktop, wait for green icon in tray.
    echo         Then run setup.bat again.
    pause
    exit /b 1
)
echo [OK] Docker is running.

docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Compose not found. Update Docker Desktop.
    pause
    exit /b 1
)
echo [OK] Docker Compose found.

echo.
echo [*] Setting up .env...
if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo [OK] .env created.
) else (
    echo [OK] .env already exists.
)

echo.
echo [*] Building Docker images (first time: 5-15 min)...
echo.
docker compose build
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo [OK] Build complete.

echo.
echo [*] Starting services...
docker compose up -d
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start!
    pause
    exit /b 1
)

echo.
echo [*] Waiting 30 seconds for startup...
timeout /t 30 /nobreak

echo.
docker compose ps

echo.
echo  ========================================
echo   GATOR PRO is RUNNING!
echo.
echo   http://localhost:8080  - Web UI
echo   http://localhost:8000  - API
echo.
echo   Login:    admin
echo   Password: GatorAdmin2024!
echo  ========================================
echo.

start http://localhost:8080

pause
