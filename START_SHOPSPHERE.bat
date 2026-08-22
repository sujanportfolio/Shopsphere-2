@echo off
cd /d "%~dp0"
start "ShopSphere Backend" cmd /k "cd backend && npm install && npm run dev"
start "ShopSphere Frontend" cmd /k "cd frontend && npm install && npm run dev"
timeout /t 5 /nobreak >nul
start http://localhost:5173
