$kani_dir = if ($env:KanidmInstallDirectory -eq $null) { "$env:ProgramFiles\kanidm" } else { $env:KanidmInstallDirectory }
$kani_dll_name = if ($env:KanidmClientDll -eq $null) { "kanidm_windows_client" } else { $env:KanidmClientDll }
$kani_dll = if ($env:KanidmClientDllPath -eq $null) { ".\$kani_dll_name.dll" } else { $env:KanidmClientDllPath }
$kani_cfg = if ($env:KanidmConfigPath -eq $null) { ".\authlib_client.toml" } else { $env:KanidmConfigPath }

if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
	Write-Output "This script must be run as an administrator"
	Return
}

if (-not (Test-Path -Path $kani_dll)) {
	Write-Output "Cannot find the kanidm config at the specified path"
	Return
}

if (-not (Test-Path -Path $kani_cfg)) {
	Write-Output "Cannot find the kanidm client dll at the specified path"
	Return
}

# Create program directory
New-Item -Path $kani_dir -ItemType Directory -Verbose

# Install kanidm authlib & config
Copy-Item $kani_dll -Destination $kani_dir
Copy-Item $kani_cfg -Destination $kani_dir

# Register DLL
$prev_sp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Security Packages"
$prev_ap = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Authentication Packages"

$new_sp = "$prev_sp\n$kani_dir\\$kani_dll_name"
$new_ap = "$prev_ap\n$kani_dir\\$kani_dll_name"

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value $new_sp
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -Value $new_ap

# Registry program path
if (-not (Test-Path -Path "HKLM:\Software\kandim")) {
	New-Item -Path "HKLM:\Software" -Name "kanidm"
}

New-ItemProperty -Path "HKLM:\Software\kanidm" -Name "InstallLocation" -Value $kani_dir -Force
