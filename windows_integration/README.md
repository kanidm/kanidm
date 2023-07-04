# kanidm Windows Client
Currently the client consists of one part, the Security Support Provider & Authentication Package (SSP/AP).

## Building
The only supported toolchain to build kanidm's Windows Client is `x86_64-pc-windows-msvc` which requires the MSVC toolchain to be installed. You can get the toolchain with the Visual Studio Workload `Desktop Development with C++`. The toolchain is also available with the same workload in the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).

## Installation
In order for the client to function, all parts must be installed in the correct place and registry values set. To install the client, run the powershell script named install.ps1.

Make sure to configure the powershell environment variables that are explained below
- KanidmInstallDirectory - Location to install the client - Default: `$env:ProgramFiles\kanidm`
- KanidmClientDll - The name of the client dll - Default: `kanidm_windows_client`
- KanidmClientDllPath - The path of the dll to copy - Default: `.\$env:KanidmClientDll.dll`
- KanidmConfigPath - The path of the config to copy - Default: `.\authlib_client.toml`

## Configuration
In order to get the client to work, all parts must be configured.

## SSP/AP
To configure the SSP/AP follow the steps below:
* Create & open a file at `C:\Program Files\kanidm\authlib_client.toml`
* Copy the skeleton template at `examples/authlib_client.toml`
* Change the uri to point towards your kanidm server
