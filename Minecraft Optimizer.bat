:start
cls
color 4
:admincheck
if not "%1"=="am_admin" (
    title Requesting admin permissions...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%0' -ArgumentList 'am_admin'"
    exit /b
)

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

Reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" && Reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t Reg_DWORD /d "2" /f
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do Reg add "%%a" /v "KMD_EnableGDIAcceleration" /t Reg_DWORD /d "1" /f

Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f
REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

title Stage 2

start /b net start STR >nul 2>&1
	if not exist SetTimerResolutionService.exe (
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

title Stage 3

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d 127.0.0.1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Compatibility-Infrastructure-Debug" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f >nul 2>nul

title Stage 4

set listofbloatware=3DBuilder Automate Appconnector Microsoft3DViewer MicrosoftPowerBIForWindows MicrosoftPowerBIForWindows Print3D XboxApp GetHelp WindowsFeedbackHub BingFoodAndDrink BingHealthAndFitness BingTravel WindowsReadingList MixedReality.Portal ScreenSketch YourPhone PicsArt-PhotoStudio EclipseManager PolarrPhotoEditorAcademicEdition Wunderlist LinkedInforWindows AutodeskSketchBook Twitter DisneyMagicKingdoms MarchofEmpires ActiproSoftwareLLC Plex iHeartRadio FarmVille2CountryEscape Duolingo CyberLinkMediaSuiteEssentials DolbyAccess DrawboardPDF FitbitCoach Flipboard Asphalt8Airborne Keeper BingNews COOKINGFEVER PandoraMediaInc CaesarsSlotsFreeCasino Shazam PhototasticCollage TuneInRadio WinZipUniversal XING RoyalRevolt2 CandyCrushSodaSaga BubbleWitch3Saga CandyCrushSaga Getstarted bing MicrosoftOfficeHub OneNote WindowsPhone SkypeApp windowscommunicationsapps WindowsMaps Sway CommsPhone ConnectivityStore Hotspot Sketchable Clipchamp Prime TikTok ToDo Family NewVoiceNote SamsungNotes SamsungFlux StudioPlus SamsungWelcome SamsungQuickSearch SamsungPCCleaner SamsungCloudBluetoothSync PCGallery OnlineSupportSService 
(for %%a in (%listofbloatware%) do ( 
	set /a insidecount+=1 >nul 2>nul
   PowerShell -Command "Get-AppxPackage -allusers *%%a* | Remove-AppxPackage"
))

title Cleaning up...

reg delete "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /v "Microsoft Edge" /f >nul 2>nul
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch_E9C49D8E9BDC4095F482C844743B9E82" /f >nul 2>nul
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch" /f >nul 2>nul
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Microsoft Edge Update" /f >nul 2>nul
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftEdgeAutoLaunch_31CF12C7FD715D87B15C2DF57BBF8D3E" /f >nul 2>nul

powershell Del /S /F /Q %Windir%\Temp >nul 2>nul

powershell Del /S /F /Q %windir%\Prefetch >nul 2>nul

powershell del %AppData%\vstelemetry >nul 2>nul
powershell del %LocalAppData%\Microsoft\VSApplicationInsights /F /Q /S >nul 2>nul
powershell del %ProgramData%\Microsoft\VSApplicationInsights  /F /Q /S >nul 2>nul
powershell del %Temp%\Microsoft\VSApplicationInsights  /F /Q /S >nul 2>nul
powershell del %Temp%\VSFaultInfo  /F /Q /S >nul 2>nul
powershell del %Temp%\VSFeedbackPerfWatsonData  /F /Q /S >nul 2>nul
powershell del %Temp%\VSFeedbackVSRTCLogs  /F /Q /S >nul 2>nul
powershell del %Temp%\VSRemoteControl  /F /Q /S >nul 2>nul
powershell del %Temp%\VSTelem /F /Q /S >nul 2>nul
powershell del %Temp%\VSTelem.Out /F /Q /S >nul 2>nul

powershell del %localappdata%\Yarn\Cache /F /Q /S >nul 2>nul

powershell del %appdata%\Microsoft\Teams\Cache /F /Q /S >nul 2>nul

powershell del %programdata%\GOG.com\Galaxy\webcache /F /Q /S >nul 2>nul
powershell del %programdata%\GOG.com\Galaxy\logs /F /Q /S >nul 2>nul

powershell del %localappdata%\Microsoft\Windows\WebCache /F /Q /S >nul 2>nul

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

title Finished!

:exit
cls
echo Exiting Minecraft Optimizer...
timeout 3 /nobreak > nul
exit
