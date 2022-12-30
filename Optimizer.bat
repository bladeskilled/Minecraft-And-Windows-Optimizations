@echo off

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

:optimize
cls
title Stage 1
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
wmic process where name="javaw.exe" CALL setpriority "realtime priority"
wmic process where name="javaw.exe" CALL setpriority "realtime priority"
cls
echo This will change your IP address only if you have a dynamic IP address, nothing else will be changed.
timeout 1 /nobreak > nul
ipconfig /flushdns
cls
mkdir C:\Optimizer
start /b net start STR >nul 2>&1
	if not exist SetTimerResolutionService.exe (
		curl -g -L -# -o "C:\Optimizer\SetTimerResolutionService.exe" "https://github.com/bladeskilled/Minecraft-Optimizer/raw/main/Optimizer/SetTimerResolutionService.exe" >nul 2>&1
		%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /i SetTimerResolutionService.exe >nul 2>&1
	)
		sc config "STR" start=auto >nul 2>&1
		start /b net start STR >nul 2>&1
		bcdedit /set disabledynamictick yes >nul 2>&1
		bcdedit /deletevalue useplatformclock >nul 2>&1
	for /F "tokens=2 delims==" %%G in (
	'wmic OS get buildnumber /value'
	) do @for /F "tokens=*" %%x in ("%%G") do (
		set "VAR=%%~x"
	)
	if !VAR! geq 19042 (
		bcdedit /deletevalue useplatformtick >nul 2>&1
	)
	if !VAR! lss 19042 (
		bcdedit /set useplatformtick yes >nul 2>&1
	)

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

powercfg -s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f

ping 127.0.0.1 -n 5 >nul
