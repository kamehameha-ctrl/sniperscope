Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "     Iniciando SniperScope // EASM & Shodan OSINT       " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Levantando Backend FastAPI (http://0.0.0.0:8000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", ".\venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "[*] Levantando Frontend Vite (http://0.0.0.0:5173)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location frontend; npm run dev -- --host 0.0.0.0"

Write-Host ""
Write-Host "[OK] Servicios iniciados. Accesos disponibles:" -ForegroundColor Green
Write-Host "     Local:  http://localhost:5173" -ForegroundColor Green
Write-Host "     Remoto: http://192.168.3.83:5173" -ForegroundColor Green
Write-Host ""
