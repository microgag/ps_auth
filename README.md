### This repo contain powershell scripts to gathner necessary logs for troubleshooting windows AD

### Check your Execution policy in your run environment
Get-ExecutionPolicy

### Types of policies
Unrestricted - All scripts can be run
Bypass - No restriction and No warning
Undefine - No execution policy is set 

### How to run
```
.\start-auth.ps1 (# accept the EULA)
.\stop-auth.ps1

folder with authlogs would be created.
```
