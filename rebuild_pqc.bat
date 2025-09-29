@echo off
chcp 65001 >nul
setlocal

:: 项目目录
cd /d D:\Users\DELL\source\repos\PQC_Project

echo === Step 1: Kill running PQC.exe process ===
taskkill /F /IM PQC.exe >nul 2>nul

echo === Step 2: Delete old PQC.exe ===
del PQC.exe >nul 2>nul

echo === Step 3: Compile PQC.c to PQC.exe ===
D:\MSYS2\mingw64\bin\gcc.exe -O2 -o PQC.exe PQC.c ^
 -ID:\MSYS2\mingw64\include ^
 -LD:\MSYS2\mingw64\lib ^
 -loqs -lcrypto

if %errorlevel% neq 0 (
    echo ❌ Build failed!
    pause
    exit /b %errorlevel%
)

echo ✅ Build success! PQC.exe generated.
pause
