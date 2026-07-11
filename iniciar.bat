@echo off
setlocal enabledelayedexpansion
title IA ORCHESTRATOR - JW Solutions

:: ================================================================
::  iniciar.bat  --  Launcher IA ORCHESTRATOR - JW Solutions
::  Sin dependencias externas (Python/Node). Usa PowerShell
::  HttpListener. Rastrea PID para shutdown limpio entre reinicios.
:: ================================================================

set "PROJECT_DIR=D:\PROYECTOS\Navegador IA"
set "PORT=8000"
set "EDGE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
set "TEMP_PS=%TEMP%\navia_server_%PORT%.ps1"
set "PID_FILE=%TEMP%\navia_server_%PORT%.pid"

echo.
echo  IA ORCHESTRATOR - JW Solutions
echo  ================================
echo.

:: ── 1. LIBERAR PUERTO ─────────────────────────────────────────────
echo  [1/4] Comprobando servidor previo...

:: Metodo primario: PID file (shutdown limpio)
if exist "!PID_FILE!" (
    set /p PREV_PID=<"!PID_FILE!"
    taskkill /PID !PREV_PID! /F >nul 2>&1
    del "!PID_FILE!" >nul 2>&1
    echo        Servidor previo detenido (PID !PREV_PID!)
)

:: Metodo secundario: netstat (por si crasheo sin PID file)
:: Nota: PID 4 = System/http.sys, nunca lo matamos
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    if not "%%a"=="4" (
        taskkill /PID %%a /F >nul 2>&1
        echo        Proceso %%a en puerto %PORT% terminado.
    )
)

:: Esperar que http.sys libere el binding (5 segundos)
ping -n 6 127.0.0.1 >nul
echo        Puerto %PORT% disponible.

:: ── 2. GENERAR SERVIDOR HTTP (PS1) ────────────────────────────────
echo  [2/4] Generando servidor HTTP...

echo $root = '%PROJECT_DIR%' > "%TEMP_PS%"
echo $port = %PORT% >> "%TEMP_PS%"
echo [IO.File]::WriteAllText("$env:TEMP\navia_server_$port.pid", "$PID") >> "%TEMP_PS%"
echo $listener = New-Object System.Net.HttpListener >> "%TEMP_PS%"
echo $listener.Prefixes.Add("http://localhost:$port/") >> "%TEMP_PS%"
echo $started = $false >> "%TEMP_PS%"
echo for ($i = 0; $i -lt 5; $i++) { >> "%TEMP_PS%"
echo     try { $listener.Start(); $started = $true; break } >> "%TEMP_PS%"
echo     catch { Start-Sleep -Seconds 2 } >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"
echo if (-not $started) { exit 1 } >> "%TEMP_PS%"
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
echo while ($listener.IsListening) { >> "%TEMP_PS%"
echo     $ctx = $listener.GetContext() >> "%TEMP_PS%"
echo     $req = $ctx.Request >> "%TEMP_PS%"
echo     $res = $ctx.Response >> "%TEMP_PS%"
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
echo         } else { >> "%TEMP_PS%"
echo             $res.StatusCode = 404 >> "%TEMP_PS%"
echo         } >> "%TEMP_PS%"
echo     } catch {} >> "%TEMP_PS%"
echo     $res.Close() >> "%TEMP_PS%"
echo } >> "%TEMP_PS%"

:: ── 3. ARRANCAR SERVIDOR EN SEGUNDO PLANO ─────────────────────────
echo  [3/4] Arrancando servidor HTTP (oculto)...
start "" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%TEMP_PS%"

:: ── 4. ESPERAR HASTA QUE EL SERVIDOR RESPONDA (max 30s) ───────────
set "TRIES=0"
:WAIT_LOOP
set /a TRIES+=1
if %TRIES% gtr 15 (
    exit /b 1
)
curl.exe -s --max-time 2 http://localhost:%PORT%/ >nul 2>nul
if errorlevel 1 (
    ping -n 2 127.0.0.1 >nul
    goto WAIT_LOOP
)
echo        Servidor activo en http://localhost:%PORT%

:: ── 5. ABRIR EDGE EN MODO APP (sin barra URL) ─────────────────────
if not exist "%EDGE%" (
    exit /b 1
)

start "" "%EDGE%" --app=http://localhost:%PORT% --new-window
