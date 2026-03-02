@echo off
echo [*] GATOR PRO Logs (press Ctrl+C to exit)
echo.
docker compose logs -f --tail=100 %1
pause
