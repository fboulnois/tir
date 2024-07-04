# TIR: A tiny Windows program to run as Trusted Installer

Trusted Installer is a system account on Windows which is more powerful than
Administrator and has full access to the system. This is useful when scripting
installation or configuration tasks, such as removing Windows Store apps or
modifying system registry keys.

TIR allows you to run any program as Trusted Installer. By default, it runs
`powershell.exe` as Trusted Installer.

## Usage

> [!CAUTION]
> Be careful when running a program as Trusted Installer, as it will have full
> access to the system. This can compromise, damage, or destroy your system.
> Only run programs you trust and understand.

### Quickstart

1. Download the latest release from the [Releases](https://github.com/fboulnois/tir/releases)
page.
2. Right-click and run `tir.exe` as an Administrator.
3. A new `powershell.exe` window will open running as Trusted Installer. You can
verify this by running `whoami` in the PowerShell window and it should return
`nt authority\system`.

### Command Line

TIR can be used to run any program as Trusted Installer. To do this, run TIR
from the command line and specify the program you want to run as a command line
argument. For example, to run `cmd.exe` as Trusted Installer, run:

```
tir.exe cmd.exe
```

## Build

TIR can be built using the included `Makefile` or `Dockerfile`. The `Makefile`
requires `x86_64-w64-mingw32-gcc` to be installed. On Debian, this is available
in the `gcc-mingw-w64-x86-64` package.