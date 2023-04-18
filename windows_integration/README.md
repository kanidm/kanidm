# kanidm Windows Client
Currently the client consists of one part, the Security Support Provider & Authentication Package (SSP/AP).

## Building
The only supported toolchain to build kanidm's Windows Client is `x86_64-pc-windows-msvc` which requires the MSVC toolchain to be installed. You can get the toolchain with the Visual Studio Workload `Desktop Development with C++`. The toolchain is also available with the same workload in the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).

## Installation
In order for the client to function, all parts must be installed in the correct place and registry values set. To install the client, run the powershell script named install.ps1 as an administrator or follow the sections below to manually install.

## SSP/AP
To install the SSP/AP follow the below steps:
* Create the directory `C:\Program Files\kanidm`
* Copy the file `kanidm_win_authlib.dll` to the newly created directory
* Set a value of `C:\Program Files\kanidm\kanidm_win_authlib` to the registry value of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages`. See the powershell example below for a quick copy and paste operation.
* The Kanidm SSP/AP is now registered and will load on the next boot, to configure the client, refer to the configuration section of this document.

For more info, refer to this [Microsoft Learn Article](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)

### Powershell to Add Authlib
```ps
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value "C:\Program Files\kanidm\kanidm_win_authlib"
```

## Configuration
In order to get the client to work, all parts must be configured.

## SSP/AP
To configure the SSP/AP follow the steps below:
* Create & open a file at `C:\Program Files\kanidm\authlib_client.toml`
* Copy the skeleton template at `examples/authlib_client.toml`
* Change the uri to point towards your kanidm server
