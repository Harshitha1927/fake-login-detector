@echo off
title Fake Login Page Detector - PhishSentry
echo =======================================================
echo     PHISHSENTRY - FAKE LOGIN PAGE DETECTOR
echo     Ethical Hacking Course Project
echo =======================================================
echo.
echo [*] Starting Flask Backend Server on http://127.0.0.1:5000...
start /b python app.py
timeout /t 3 /nobreak >nul
echo.
echo [*] Exposing Public HTTPS URL via Cloudflare Tunnel...
echo.
.\bin\cloudflared.exe tunnel --url http://127.0.0.1:5000
pause
