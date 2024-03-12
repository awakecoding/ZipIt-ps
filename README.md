# ZipIt: raw zip file format editing PowerShell cmdlets

## Installation

```powershell
Install-Module -Name ZipIt -Force
```

## Usage

```powershell
Import-Module ZipIt
Get-Command -Module ZipIt
```

Set unix file permissions "r-xr-xr-x" (555) on all files matching pattern "native/ssh$" inside zip file "zip-test.zip":

```powershell
Set-ZipItUnixFilePermissions "zip-test.zip" -FilePattern "native/ssh$" -FilePermissions "r-xr-xr-x"
```
