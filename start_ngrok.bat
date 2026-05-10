@echo off
title SecureFS ngrok Tunnel
color 0a

echo ===================================================
echo        Starting SecureFS Tunnel via ngrok
echo ===================================================
echo.
echo Your permanent URL is:
echo https://handgrip-gills-coziness.ngrok-free.dev
echo.
echo Make sure your Python server is running in another window!
echo.

ngrok http --url=handgrip-gills-coziness.ngrok-free.dev 8443

pause
