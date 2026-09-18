$projectPath = "C:\Users\LENOVO\OneDrive\Desktop\NIDS_PROJECTS"

Set-Location $projectPath

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "          BASIC NIDS STARTING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path ".\app.py")) {

    Write-Host "ERROR: app.py not found." -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit
}

# Stop VS Code Live Server / other process on port 5500
Write-Host "Checking port 5500..." -ForegroundColor Yellow

$liveServer = Get-NetTCPConnection `
    -LocalPort 5500 `
    -State Listen `
    -ErrorAction SilentlyContinue

if ($liveServer) {

    foreach ($connection in $liveServer) {

        $pidNumber = $connection.OwningProcess

        Write-Host "Stopping process on port 5500: PID $pidNumber" -ForegroundColor Yellow

        Stop-Process `
            -Id $pidNumber `
            -Force `
            -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}

# Stop old Flask process on port 5000
Write-Host "Checking port 5000..." -ForegroundColor Yellow

$oldFlask = Get-NetTCPConnection `
    -LocalPort 5000 `
    -State Listen `
    -ErrorAction SilentlyContinue

if ($oldFlask) {

    foreach ($connection in $oldFlask) {

        $pidNumber = $connection.OwningProcess

        Write-Host "Stopping old Flask process: PID $pidNumber" -ForegroundColor Yellow

        Stop-Process `
            -Id $pidNumber `
            -Force `
            -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}

Write-Host "Starting Flask NIDS..." -ForegroundColor Yellow

Start-Process `
    -FilePath "python" `
    -ArgumentList "app.py" `
    -WorkingDirectory $projectPath

Write-Host "Waiting for Flask server..." -ForegroundColor Yellow

$serverReady = $false

for ($i = 1; $i -le 20; $i++) {

    Start-Sleep -Seconds 1

    try {

        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:5000/" `
            -UseBasicParsing `
            -TimeoutSec 2 `
            -ErrorAction Stop

        if ($response.StatusCode -eq 200) {

            $serverReady = $true
            break
        }

    }
    catch {
        # Flask is still starting
    }

    Write-Host "Waiting... $i/20" -ForegroundColor Gray
}

if (-not $serverReady) {

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "FLASK SERVER DID NOT START" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""

    Read-Host "Press Enter to close"
    exit
}

Write-Host ""
Write-Host "FLASK SERVER READY." -ForegroundColor Green
Write-Host ""
Write-Host "Opening NIDS LOGIN..." -ForegroundColor Green

Start-Process "http://127.0.0.1:5000/"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "          BASIC NIDS IS RUNNING" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Correct URL:" -ForegroundColor Cyan
Write-Host "http://127.0.0.1:5000/" -ForegroundColor White
Write-Host ""
Write-Host "DO NOT USE PORT 5500." -ForegroundColor Yellow
Write-Host ""
