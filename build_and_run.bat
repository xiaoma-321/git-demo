@echo off
setlocal

:: 设置路径（修正为您的实际路径）
set PATH=D:\MSYS2\mingw64\bin;%PATH%

:: 项目路径
cd /d D:\Users\DELL\source\repos\PQC_Project

echo === 编译 PQC.c 中，请稍候... ===

gcc PQC.c -o PQC.exe ^
 -O2 ^
 -I D:\MSYS2\mingw64\include ^
 -L D:\MSYS2\mingw64\lib ^
 -loqs -lcrypto

if %errorlevel% neq 0 (
    echo 编译失败，请检查错误！
    pause
    exit /b %errorlevel%
)

echo === 编译完成，开始运行 PQC.exe ===
echo.

PQC.exe

echo.
pause