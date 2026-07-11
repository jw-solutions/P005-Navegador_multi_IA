@echo off
setlocal enabledelayedexpansion
title IA ORCHESTRATOR DEBUG - Servidor Visible

:: ================================================================
::  debug.bat  --  Modo diagnostico para IA ORCHESTRATOR - JW Solutions
::  Misma logica que iniciar.bat pero con ventana de PowerShell
::  VISIBLE para ver errores .NET en tiempo real.
::  Usar cuando iniciar.bat falla silenciosamente.
:: ================================================================

set "PROJECT_DIR=D:\PROYECTOS\Navegador IA"
set "PORT=8000"
set "EDGE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
set "TEMP_PS=%TEMP%\navia_debug_%PORT%.ps1"
set "PID_FILE=%TEMP%\navia_server_%PORT%.pid"

echo.
echo  ===================================================
echo   IA ORCHESTRATOR DEBUG - Ventana de servidor visible
echo  ===================================================
echo.

:: ── 1. LIBERAR PUERTO ─────────────────────────────────────────
echo  Liberando puerto %PORT%...
if exist "!PID_FILE!" (
    set /p PREV_PID=<"!PID_FILE!"
    taskkill /PID !PREV_PID! /F >nul 2>&1
    del "!PID_FILE!" >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    if not "%%a"=="4" ( taskkill /PID %%a /F >nul 2>&1 )
)
ping -n 6 127.0.0.1 >nul
echo  Puerto liberado. Esperando 5 segundos para http.sys...

:: ── 2. GENERAR PS1 VERBOSE (con Write-Host para diagnostico) ──
echo  Generando script de diagnostico...

echo Write-Host "=== NavIA Debug Server ===" > "%TEMP_PS%"
echo Write-Host "Root: %PROJECT_DIR%" >> "%TEMP_PS%"
echo Write-Host "Port: %PORT%" >> "%TEMP_PS%"
echo $root = '%PROJECT_DIR%' >> "%TEMP_PS%"
echo $port = %PORT% >> "%TEMP_PS%"
echo [IO.File]::WriteAllText("$env:TEMP\navia_server_$port.pid", "$PID") >> "%TEMP_PS%"
echo $listener = New-Object System.Net.HttpListener >> "%TEMP_PS%"
echo $listener.Prefixes.Add("http://localhost:$port/") >> "%TEMP_PS%"
echo Write-Host "Prefijo configurado: http://localhost:$port/" >> "%TEMP_PS%"
echo $started = $false >> "%TEMP_PS%"
echo for ($i = 0; $i -lt 5; $i++) { >> "%TEMP_PS%"
echo     Write-Host "Intento $($i+1)/5 de iniciar HttpListener..." >> "%TEMP_PS%"
echo     try { >> "%TEMP_PS%"
echo         $listener.Start() >> "%TEMP_PS%"
echo         $started = $true >> "%TEMP_PS%"
echo         Write-Host "OK - HttpListener activo en puerto $port" >> "%TEMP_PS%"
echo         break >> "%TEMP_PS%"
echo     } catch { >> "%TEMP_PS%"
echo         Write-Host "FALLO: $_" >> "%TEMP_PS%"
echo         if ($i -lt 4) { Write-Host "Reintentando en 2 segundos..."; Start-Sleep -Seconds 2 } >> "%TEMP_PS%"
echo     } >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"
echo if (-not $started) { >> "%TEMP_PS%"
echo     Write-Host "" >> "%TEMP_PS%"
echo     Write-Host "FATAL: No se pudo iniciar el servidor tras 5 intentos." >> "%TEMP_PS%"
echo     Write-Host "Posibles causas:" >> "%TEMP_PS%"
echo     Write-Host "  - Puerto %PORT% bloqueado por otra app" >> "%TEMP_PS%"
echo     Write-Host "  - http.sys aun no libero el binding (espera 10s y reintenta)" >> "%TEMP_PS%"
echo     Write-Host "  - Firewall de Windows bloqueando HttpListener" >> "%TEMP_PS%"
echo     Read-Host "Presiona Enter para cerrar" >> "%TEMP_PS%"
echo     exit 1 >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"
echo $mime = @{ >> "%TEMP_PS%"
echo     '.html'  = 'text/html; charset=utf-8' >> "%TEMP_PS%"
echo     '.js'    = 'application/javascript; charset=utf-8' >> "%TEMP_PS%"
echo     '.css'   = 'text/css; charset=utf-8' >> "%TEMP_PS%"
echo     '.json'  = 'application/json; charset=utf-8' >> "%TEMP_PS%"
echo     '.ico'   = 'image/x-icon' >> "%TEMP_PS%"
echo     '.png'   = 'image/png' >> "%TEMP_PS%"
echo     '.svg'   = 'image/svg+xml' >> "%TEMP_PS%"
echo     '.woff2' = 'font/woff2' >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"
echo Write-Host "" >> "%TEMP_PS%"
echo Write-Host "Servidor HTTP listo. Esperando peticiones en http://localhost:$port" >> "%TEMP_PS%"
echo Write-Host "(Ctrl+C para detener)" >> "%TEMP_PS%"
echo Write-Host "" >> "%TEMP_PS%"
echo while ($listener.IsListening) { >> "%TEMP_PS%"
echo     $ctx = $listener.GetContext() >> "%TEMP_PS%"
echo     $req = $ctx.Request >> "%TEMP_PS%"
echo     $res = $ctx.Response >> "%TEMP_PS%"
echo     Write-Host "$($req.HttpMethod) $($req.Url.LocalPath)" -NoNewline >> "%TEMP_PS%"
echo     try { >> "%TEMP_PS%"
echo         $p = $req.Url.LocalPath >> "%TEMP_PS%"
echo         if ($p -eq '/' -or $p -eq '') { $p = '/index.html' } >> "%TEMP_PS%"
echo         $fp = Join-Path $root ($p.TrimStart('/').Replace('/', '\')) >> "%TEMP_PS%"
echo         if (Test-Path $fp -PathType Leaf) { >> "%TEMP_PS%"
echo             $b = [IO.File]::ReadAllBytes($fp) >> "%TEMP_PS%"
echo             $ext = [IO.Path]::GetExtension($fp).ToLower() >> "%TEMP_PS%"
echo             $res.ContentType = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' } >> "%TEMP_PS%"
echo             $res.ContentLength64 = $b.Length >> "%TEMP_PS%"
echo             $res.OutputStream.Write($b, 0, $b.Length) >> "%TEMP_PS%"
echo             Write-Host "  ->  200 OK  [$($b.Length) bytes]  $($res.ContentType)" >> "%TEMP_PS%"
echo         } else { >> "%TEMP_PS%"
echo             $res.StatusCode = 404 >> "%TEMP_PS%"
echo             Write-Host "  ->  404 Not Found  ($fp)" >> "%TEMP_PS%"
echo         } >> "%TEMP_PS%"
echo     } catch { Write-Host "  ->  ERROR: $_" } >> "%TEMP_PS%"
echo     $res.Close() >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"

:: ── 3. ARRANCAR SERVIDOR VISIBLE (SIN OCULTAR) ────────────────
echo.
echo  Iniciando servidor VISIBLE en nueva ventana de PowerShell...
echo  Observa esa ventana para diagnosticar cualquier error.
echo.
start "IA ORCHESTRATOR Debug Server" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS%"

:: ── 4. ESPERAR Y VERIFICAR ────────────────────────────────────
echo  Esperando que el servidor responda...
set "TRIES=0"
:WAIT_LOOP
set /a TRIES+=1
if %TRIES% gtr 20 (
    echo.
    echo  El servidor no respondio en 40 segundos.
    echo  Revisa la ventana de PowerShell para ver el error exacto.
    echo.
    pause
    exit /b 1
)
curl.exe -s --max-time 2 http://localhost:%PORT%/ >nul 2>nul
if errorlevel 1 (
    ping -n 2 127.0.0.1 >nul
    goto WAIT_LOOP
)
echo  Servidor respondiendo correctamente en http://localhost:%PORT%

:: ── 5. ABRIR EDGE ─────────────────────────────────────────────
if not exist "%EDGE%" (
    echo  Edge no encontrado. Abre manualmente: http://localhost:%PORT%
    pause
    exit /b 1
)
echo  Abriendo Edge...
start "" "%EDGE%" --app=http://localhost:%PORT% --new-window

echo.
echo  Modo debug activo.
echo  Cierra la ventana de PowerShell para detener el servidor.
echo.
pause
