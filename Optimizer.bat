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
ping 127.0.0.1 -n 5 >nul
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
		curl -g -L -# -o "C:\Optimizer\SetTimerResolutionService.exe" "https://github.com/auraside/HoneCtrl/raw/main/Files/SetTimerResolutionService.exe" >nul 2>&1
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

reg delete "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /v "Microsoft Edge" /f >nul 2>nul
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch_E9C49D8E9BDC4095F482C844743B9E82" /f >nul 2>nul
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch" /f >nul 2>nul
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Microsoft Edge Update" /f >nul 2>nul
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch_31CF12C7FD715D87B15C2DF57BBF8D3E" /f >nul 2>nul

powershell del "%SystemDrive%\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Directx.log" /F /Q >nul 2>nul
powershell del "%WinDir%\SchedLgU.txt" /F /Q >nul 2>nul
powershell del "%WinDir%\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\security\logs\*.old" /F /Q >nul 2>nul
powershell del "%WinDir%\security\logs\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Debug\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Debug\UserMode\*.bak" /F /Q >nul 2>nul
powershell del "%WinDir%\Debug\UserMode\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\*.bak" /F /Q >nul 2>nul
powershell del "%WinDir%\system32\wbem\Logs\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\OEWABLog.txt" /F /Q >nul 2>nul
powershell del "%WinDir%\setuplog.txt" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\DISM\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\*.log.txt" /F /Q >nul 2>nul
powershell del "%WinDir%\APPLOG\*.*" /F /Q >nul 2>nul
powershell del "%WinDir%\system32\wbem\Logs\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\system32\wbem\Logs\*.lo_" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\DPX\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\ServiceProfiles\NetworkService\AppData\Local\Temp\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\*.log" /F /Q >nul 2>nul
powershell del "%LocalAppData%\Microsoft\Windows\WindowsUpdate.log" /F /Q >nul 2>nul
powershell del "%LocalAppData%\Microsoft\Windows\WebCache\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Panther\cbs.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Panther\DDACLSys.log" /F /Q >nul 2>nul
powershell del "%WinDir%\repair\setup.log" /F /Q >nul 2>nul
powershell del "%WinDir%\Panther\UnattendGC\diagerr.xml" /F /Q >nul 2>nul
powershell del "%WinDir%\Panther\UnattendGC\diagwrn.xml" /F /Q >nul 2>nul
powershell del "%WinDir%\inf\setupapi.offline.log" /F /Q >nul 2>nul
powershell del "%WinDir%\inf\setupapi.app.log" /F /Q >nul 2>nul
powershell del "%WinDir%\debug\WIA\*.log" /F /Q >nul 2>nul
powershell del "%SystemDrive%\PerfLogs\System\Diagnostics\*.*" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\CBS\*.cab" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\CBS\*.cab" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs\WindowsBackup\*.etl" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\LogFiles\HTTPERR\*.*" /F /Q >nul 2>nul
powershell del "%WinDir%\SysNative\SleepStudy\*.etl" /F /Q >nul 2>nul
powershell del "%WinDir%\SysNative\SleepStudy\ScreenOn\*.etl" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\SleepStudy\*.etl" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\SleepStudy\ScreenOn\*.etl" /F /Q >nul 2>nul
powershell del "%WinDir%\Logs" /F /Q >nul 2>nul
powershell del "%WinDir%\DISM" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\catroot2\*.chk" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\catroot2\*.log" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\catroot2\.jrs" /F /Q >nul 2>nul
powershell del "%WinDir%\System32\catroot2\*.txt" /F /Q >nul 2>nul