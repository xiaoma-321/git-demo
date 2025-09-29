@echo off
chcp 65001 >nul
setlocal

cd /d D:\Users\DELL\source\repos\PQC_Project

echo ======================================
echo   启动 Node.js 服务 (server.js)
echo   (使用 Ctrl+C 停止服务)
echo ======================================
echo.

:: 使用 Node.js 的绝对路径启动
"D:\node.exe" server.js

:: 只有当 Node.js 服务真正退出时，才会走到这里
echo.
echo ======================================
echo   Node.js 服务已退出
echo ======================================
pause
endlocal
