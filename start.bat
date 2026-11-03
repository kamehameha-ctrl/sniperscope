@echo off
echo ========================================================
echo      Iniciando SniperScope // EASM & Shodan OSINT
echo ========================================================
echo.

:: Iniciar Backend FastAPI en todas las interfaces (0.0.0.0)
echo [*] Levantando Backend FastAPI en http://0.0.0.0:8000 ...
start "SniperScope - Backend FastAPI" cmd /k ".\venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

:: Iniciar Frontend Vite en todas las interfaces (0.0.0.0)
echo [*] Levantando Frontend Vite en http://0.0.0.0:5173 ...
cd frontend
start "SniperScope - Frontend Web" cmd /k "npm run dev -- --host 0.0.0.0"

echo.
echo [OK] Ambos servicios iniciados.
echo      Local:  http://localhost:5173
echo      Remoto: http://192.168.3.83:5173
echo.
pause
