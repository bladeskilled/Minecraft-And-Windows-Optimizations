@echo off
echo Made by BladeSkilled, Optimizations by HoneCtrl.

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

mkdir C:\Hone >nul 2>&1
mkdir C:\Hone\Resources

curl -g -k -L -# -o "C:\Hone\Resources\HoneV2.pow" "https://github.com/auraside/HoneCtrl/raw/main/Files/HoneV2.pow" >nul 2>&1
powercfg /d 44444444-4444-4444-4444-444444444449 >nul 2>&1
powercfg -import "C:\Hone\Resources\HoneV2.pow" 44444444-4444-4444-4444-444444444449 >nul 2>&1
powercfg /changename 44444444-4444-4444-4444-444444444449 "Hone Ultimate Power Plan V2 | Install By BladeSkilled" "The Ultimate Power Plan to increase FPS, improve latency and reduce input lag." >nul 2>&1

cd C:\Hone\Resources
sc config "STR" start= auto >nul 2>&1
start /b net start STR >nul 2>&1
	if not exist SetTimerResolutionService.exe (
		::https://forums.guru3d.com/threads/windows-timer-resolution-tool-in-form-of-system-service.376458/
		curl -g -L -# -o "C:\Hone\Resources\SetTimerResolutionService.exe" "https://github.com/auraside/HoneCtrl/raw/main/Files/SetTimerResolutionService.exe" >nul 2>&1
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

    Reg add "HKCU\Software\Hone" /v InternetTweaks /f
    netsh int tcp set global dca=enabled
    netsh int tcp set global netdma=enabled
    netsh interface isatap set state disabled
    netsh int tcp set global timestamps=disabled
    netsh int tcp set global rss=enabled
    netsh int tcp set global nonsackrttresiliency=disabled
    netsh int tcp set global initialRto=2000
    netsh int tcp set supplemental template=custom icw=10


cls
Reg add "HKCU\Software\Hone" /v "AllGPUTweaks" /f
::Enable Hardware Accelerated Scheduling
Reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" && Reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t Reg_DWORD /d "2" /f
::Enable gdi hardware acceleration
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do Reg add "%%a" /v "KMD_EnableGDIAcceleration" /t Reg_DWORD /d "1" /f

Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f

Reg add "HKCU\Software\Hone" /v MitigationsTweaks /f
	::Turn Core Isolation Memory Integrity OFF
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
	::Disable SEHOP
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t Reg_DWORD /d "1" /f
	::Disable Spectre And Meltdown
    Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
    Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
    Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
	cd %temp%
	if not exist "%temp%\NSudo.exe" curl -g -L -# -o "%temp%\NSudo.exe" "https://github.com/auraside/HoneCtrl/raw/main/Files/NSudo.exe"
	NSudo -U:S -ShowWindowMode:Hide -wait cmd /c "Reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t Reg_DWORD /d "3" /f"
	NSudo -U:S -ShowWindowMode:Hide -wait cmd /c "sc start "TrustedInstaller"
	NSudo -U:T -P:E -M:S -ShowWindowMode:Hide -wait cmd /c "ren %WinDir%\System32\mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.old"
	NSudo -U:T -P:E -M:S -ShowWindowMode:Hide -wait cmd /c "ren %WinDir%\System32\mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.old"
	::Disable CFG Lock
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t Reg_DWORD /d "0" /f
	::Disable NTFS/ReFS and FS Mitigations
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t Reg_DWORD /d "0" /f
	::Disable System Mitigations
    for /f "tokens=3 skip=2" %%i in ('reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%i
    for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
    Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f
    Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f

for /f %%i in ('Reg query "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
		Reg add "%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul 2>&1

Reg add "HKCU\Software\Hone" /v DUSBPowerSavings /f
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr "StorPort"') do Reg add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f
	for /f "tokens=*" %%i in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr "USB\VID_"') do (
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
	Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f


cls
Reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000156e000000000000004001000000000029dc0300000000000000280000000000" /f >nul 2>&1
Reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000fd11010000000000002404000000000000fc12000000000000c0bb0100000000" /f >nul 2>&1


REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
pause

