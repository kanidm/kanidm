# Kanidm Windows Client
Currently the client consists of one part, the Security Support Provider & Authentication Package (SSP/AP).

## Building
The only supported toolchain to build Kanidm's Windows Client is `x86_64-pc-windows-msvc` which requires the MSVC toolchain to be installed. You can get the toolchain with the Visual Studio Workload `Desktop Development with C++`. The toolchain is also available with the same workload in the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).

## Installation
In order for the client to function, all parts must be installed in the correct place and registry values set. In the future there will be a powershell script and maybe MSI package to automate this.

## SSP/AP
To install the SSP/AP follow the below steps:
* Create the directory `C:\Program Files\kanidm`
* Place the DLL for the SSP/AP into the newly created directory
* Open the Registry Editor and navigate to `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`
* Add the path `C:\Program Files\kandim\kanidm-ssp-ap\0` (The \0 is a null character)
* The Kanidm SSP/AP is now registered and will load on the next boot

For more info, refer to this [Microsoft Learn Article](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
