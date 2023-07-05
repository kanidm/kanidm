$kani_dir = if ($env:KanidmInstallDirectory -eq $null) { "$env:ProgramFiles\kanidm" } else { $env:KanidmInstallDirectory }

if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
	Write-Output "This script must be run as an administrator"
	Return
}

# Delete program dir
Remove-Item -Recurse -Path $kani_dir

# Unregister DLLs & delete cfg
Clear-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Security Packages"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -Value "msv1_0"

Remove-Item -Path "HKLM:\Software\kanidm" -Recurse