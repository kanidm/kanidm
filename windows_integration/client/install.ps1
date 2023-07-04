$kani_dir = "$env:ProgramFiles\kanidm"

if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
	Write-Output "This script must be run as an administrator"
	Return
}

if (-not (Test-Path -Path .\kanidm_windows_client.dll) -or -not (Test-Path -Path .\authlib_client.toml)) {
	Write-Output "Cannot find the authlib config or dll in the present directory"
	Return
}

# Create program directory
New-Item -Path $kani_dir -ItemType Directory -Verbose

# Install kanidm authlib & config
Copy-Item .\kanidm_windows_client.dll -Destination $kani_dir
Copy-Item .\authlib_client.toml -Destination $kani_dir

# Register DLL
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value "C:\Program Files\kanidm\kanidm_windows_client"
