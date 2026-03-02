@echo off
echo.
echo [*] Stopping GATOR PRO Enterprise...
docker compose down
echo.
echo [OK] All services stopped. Data is preserved.
echo      To delete ALL data: docker compose down -v
echo.
pause
