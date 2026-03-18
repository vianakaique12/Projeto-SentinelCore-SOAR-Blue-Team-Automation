$ErrorActionPreference = "Stop"

docker compose up --build -d

Write-Host ""
Write-Host "Mini SOAR stack iniciado."
Write-Host "API:     http://127.0.0.1:8000"
Write-Host "Swagger: http://127.0.0.1:8000/docs"
Write-Host "Health:  http://127.0.0.1:8000/health"

