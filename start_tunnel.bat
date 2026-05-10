@echo off
title SecureFS Online Tunnel
color 0b

echo ===================================================
echo     Starting SecureFS Tunnel via localhost.run
echo ===================================================
echo.
echo Please wait while the secure tunnel is established...
echo Look for the "https://[something].lhr.life" URL below!
echo.

ssh -o StrictHostKeyChecking=accept-new -R 80:127.0.0.1:8443 nokey@localhost.run

echo.
echo Tunnel closed.
pause
