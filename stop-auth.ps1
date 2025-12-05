<#
   ***Directory Services Authentication Scripts***

   Requires: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)

   Last Updated: 2025-10-09
   
   Version: 6.3
#>
#Requires -RunAsAdministrator

$global:ScriptPrefix = 'auth'
$global:_BASE_LOG_DIR = ".\authlogs"
$global:_LOG_DIR = $_BASE_LOG_DIR
$global:ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType

# *** Set some system specifc variables ***
$global:wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
$global:osVersionString = $wmiOSObject.Version
$global:osBuildNumString = $wmiOSObject.BuildNumber

function Stop-Logman {
    param(
        [string]$TraceName,
        [bool]$Persist
    )
    if($TraceName -eq "NT Kernel Logger"){
        logman stop "$TraceName" -ets
    }
    else{$prefixedTraceName = "auth_" + $TraceName
        logman stop "$prefixedTraceName" -ets
        if($Persist) {
            logman delete "autosession\$prefixedTraceName" -ets
        }
    }
}

#load module
$Scriptfolder = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

foreach($file in Get-ChildItem $Scriptfolder){
	$extension = [IO.Path]::GetExtension($file)
	if (($extension -eq ".psm1") -and ($file.Name -eq "TSS_AUT.psm1") ){
		$modName = ($file.Name).substring(0, ($file.Name).length - 5)
		$modPath = "$Scriptfolder\$($file.Name)"
		Remove-Module $modName -ErrorAction Ignore
		#LogDebug ("Remove module for $modName completed")
		Import-Module $modPath -DisableNameChecking
		#LogDebug ("Import module for $modPath completed")
	}
}

# ***STOP LOGMAN TRACING***
$NGCSingleTraceName = "NGC"
$BiometricSingleTraceName = "Biometric"
$LSASingleTraceName = "LSA"
$Ntlm_CredSSPSingleTraceName = "Ntlm_CredSSP"
$KerberosSingleTraceName = "Kerberos"
$KDCSingleTraceName = "KDC"
$SSLSingleTraceName = "SSL"
$WebauthSingleTraceName = "Webauth"
$SmartcardSingleTraceName = "Smartcard"
$CredprovAuthuiSingleTraceName = "CredprovAuthui"
$CryptNcryptDpapiSingleTraceName = "CryptNcryptDpapi"
$SAMSingleTraceName = "SAM"
$SSPICliSingleTraceName = "SSPICli"
$KsecDDSingleTraceName = "KsecDD"
$AppxSingleTraceName = "AppX"
$KernelSingleTraceName = "NT Kernel Logger"
$GPSVCSingleTraceName = "GPSVC"

[bool] $persist = $false  #POC wout autologger

# *** Disclaimer ***
Write-Host "`n
***************** Microsoft CSS Authentication Scripts ****************`n
This Data collection is for Authentication, smart card and Credential provider scenarios.`n
This script will stop the tracing that was previously activated with the start-auth.ps1 script.
Data is collected into a subdirectory of the directory from where this script is launched, called ""authlogs"".`n
Please wait whilst the tracing stops and data is collected....
"

$scriptInfo = Get-Content $_LOG_DIR\script-info.txt
$persist = ($scriptInfo | Where-Object { $_ -match "persist" }) -ne $null

#region ***STOP LOGMAN TRACING***

# Stop NGC logman
Stop-Logman -TraceName $NGCSingleTraceName -Persist $persist

# Stop Biometric logman
Stop-Logman -TraceName $BiometricSingleTraceName -Persist $persist

# Stop LSA logman
Stop-Logman -TraceName $LSASingleTraceName -Persist $persist

# Stop Ntlm_CredSSP logman
Stop-Logman -TraceName $Ntlm_CredSSPSingleTraceName -Persist $persist

# Stop Kerberos logman
Stop-Logman -TraceName $KerberosSingleTraceName -Persist $persist

# Stop KDC logman
if ($global:ProductType -eq "LanmanNT") { 
    Stop-Logman -TraceName $KDCSingleTraceName -Persist $persist 
}

# Stop SSL logman
Stop-Logman -TraceName $SSLSingleTraceName -Persist $persist

# Stop Webauth logman
Stop-Logman -TraceName $WebauthSingleTraceName -Persist $persist

# Stop Smartcard logman
Stop-Logman -TraceName $SmartcardSingleTraceName -Persist $persist

# Stop CredprovAuthui logman
Stop-Logman -TraceName $CredprovAuthuiSingleTraceName -Persist $persist

# Check if the '-vAuth' switch was passed
$CheckIfvAuthWasPassed = (get-content $_LOG_DIR\script-info.txt | Select-String -pattern "passed: vAuth") -ne $null

# Stop CryptNcryptDpapi logman
if ($global:ProductType -eq "WinNT") {
    Stop-Logman -TraceName $CryptNcryptDpapiSingleTraceName -Persist $persist
} elseif($CheckIfvAuthWasPassed) {
    Stop-Logman -TraceName $CryptNcryptDpapiSingleTraceName -Persist $persist 
}

# Stop SAM logman
Stop-Logman -TraceName $SAMSingleTraceName -Persist $persist

# Stop SSPICli logman
Stop-Logman -TraceName $SSPICliSingleTraceName -Persist $persist

# Stop KsecDD logman
Stop-Logman -TraceName $KsecDDSingleTraceName -Persist $persist

# Stop AppX logman
if (($global:ProductType -eq "WinNT") -or ($CheckIfvAuthWasPassed -and ($global:ProductType -ne "LanmanNT"))) {
   Stop-Logman -TraceName $AppxSingleTraceName -Persist $persist
}

# Stop Kernel logman
if ($global:ProductType -eq "WinNT") { 
    if(!$persist) {
        Stop-Logman -TraceName $KernelSingleTraceName -Persist $false 
    }
}

# Stop Logman GPSVC
if([version]$osVersionString -ge [version]"10.0.22621"){
    Stop-Logman -TraceName $GPSVCSingleTraceName -Persist $persist
}

#endregion ***STOP LOGMAN TRACING***

# *** CollectADS_AuthLog (Stops the data Collection) ***
CollectADS_AuthLog


# SIG # Begin signature block
# MIIoPAYJKoZIhvcNAQcCoIIoLTCCKCkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB37rFLpv2NXBXZ
# bVeNiNAEf/dgMv742BSVqd4g7Zp1+KCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
# EuB4ozFdAAAAAASEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM1WhcNMjYwNjE3MTgyMTM1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDtekqMKDnzfsyc1T1QpHfFtr+rkir8ldzLPKmMXbRDouVXAsvBfd6E82tPj4Yz
# aSluGDQoX3NpMKooKeVFjjNRq37yyT/h1QTLMB8dpmsZ/70UM+U/sYxvt1PWWxLj
# MNIXqzB8PjG6i7H2YFgk4YOhfGSekvnzW13dLAtfjD0wiwREPvCNlilRz7XoFde5
# KO01eFiWeteh48qUOqUaAkIznC4XB3sFd1LWUmupXHK05QfJSmnei9qZJBYTt8Zh
# ArGDh7nQn+Y1jOA3oBiCUJ4n1CMaWdDhrgdMuu026oWAbfC3prqkUn8LWp28H+2S
# LetNG5KQZZwvy3Zcn7+PQGl5AgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUBN/0b6Fh6nMdE4FAxYG9kWCpbYUw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwNTM2MjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AGLQps1XU4RTcoDIDLP6QG3NnRE3p/WSMp61Cs8Z+JUv3xJWGtBzYmCINmHVFv6i
# 8pYF/e79FNK6P1oKjduxqHSicBdg8Mj0k8kDFA/0eU26bPBRQUIaiWrhsDOrXWdL
# m7Zmu516oQoUWcINs4jBfjDEVV4bmgQYfe+4/MUJwQJ9h6mfE+kcCP4HlP4ChIQB
# UHoSymakcTBvZw+Qst7sbdt5KnQKkSEN01CzPG1awClCI6zLKf/vKIwnqHw/+Wvc
# Ar7gwKlWNmLwTNi807r9rWsXQep1Q8YMkIuGmZ0a1qCd3GuOkSRznz2/0ojeZVYh
# ZyohCQi1Bs+xfRkv/fy0HfV3mNyO22dFUvHzBZgqE5FbGjmUnrSr1x8lCrK+s4A+
# bOGp2IejOphWoZEPGOco/HEznZ5Lk6w6W+E2Jy3PHoFE0Y8TtkSE4/80Y2lBJhLj
# 27d8ueJ8IdQhSpL/WzTjjnuYH7Dx5o9pWdIGSaFNYuSqOYxrVW7N4AEQVRDZeqDc
# fqPG3O6r5SNsxXbd71DCIQURtUKss53ON+vrlV0rjiKBIdwvMNLQ9zK0jy77owDy
# XXoYkQxakN2uFIBO1UNAvCYXjs4rw3SRmBX9qiZ5ENxcn/pLMkiyb68QdwHUXz+1
# fI6ea3/jjpNPz6Dlc/RMcXIWeMMkhup/XEbwu73U+uz/MIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAASEmOIS4HijMV0AAAAA
# BIQwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHBI
# UhT//n1a7P+euAI5LtvrXvyLbGuh+IXhTH0x5wzTMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAQ+eyyDID2/jiZpEugAQVf0KedkSVipBOZpNz
# pUFDXJfL4eDwzjpKT5j2JDVBN3Hqtjt417bDyD4EqgTIa6OPQXvW1CnjKWL1S8ev
# 8XjhEDfq1L5vA+uzs97CxTZDftlDH12BZ4Q1IcCm+nTgikZh8AUQqZEeNQ3dmly3
# SiR8EXCOilynNOJr2j8be/10uQvk7GlRfgRNjpZFzzj2FMcYaUoBChTy6ZZkhE4p
# fkujSrKOhi2HnjjlpbcOAX+opuvhVkGDq1cj53olxz5cZU6a+Tbf+2GMJgVJ7ljw
# +JUBcOhe+rhWorzAhuLkf7r9mJ/dPFbI5gWIoNIjkxBql+QTYaGCF5cwgheTBgor
# BgEEAYI3AwMBMYIXgzCCF38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAL4Ep1Dog0Vk6ua483N8O1rnwR6Ys1baoI
# eZZquWlWUQIGaMmGO+/IGBMyMDI1MTAwOTEyMTQyMy40MzRaMASAAgH0oIHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WgghHtMIIHIDCCBQigAwIBAgITMwAAAgcsETmJzYX7xQAB
# AAACBzANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDAeFw0yNTAxMzAxOTQyNTJaFw0yNjA0MjIxOTQyNTJaMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046ODYwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDFP/96dPmcfgODe3/nuFve
# uBst/JmSxSkOn89ZFytHQm344iLoPqkVws+CiUejQabKf+/c7KU1nqwAmmtiPnG8
# zm4Sl9+RJZaQ4Dx3qtA9mdQdS7Chf6YUbP4Z++8laNbTQigJoXCmzlV34vmC4zpF
# rET4KAATjXSPK0sQuFhKr7ltNaMFGclXSnIhcnScj9QUDVLQpAsJtsKHyHN7cN74
# aEXLpFGc1I+WYFRxaTgqSPqGRfEfuQ2yGrAbWjJYOXueeTA1MVKhW8zzSEpfjKeK
# /t2XuKykpCUaKn5s8sqNbI3bHt/rE/pNzwWnAKz+POBRbJxIkmL+n/EMVir5u8uy
# WPl1t88MK551AGVh+2H4ziR14YDxzyCG924gaonKjicYnWUBOtXrnPK6AS/LN6Y+
# 8Kxh26a6vKbFbzaqWXAjzEiQ8EY9K9pYI/KCygixjDwHfUgVSWCyT8Kw7mGByUZm
# RPPxXONluMe/P8CtBJMpuh8CBWyjvFfFmOSNRK8ETkUmlTUAR1CIOaeBqLGwscSh
# FfyvDQrbChmhXib4nRMX5U9Yr9d7VcYHn6eZJsgyzh5QKlIbCQC/YvhFK42ceCBD
# Mbc+Ot5R6T/Mwce5jVyVCmqXVxWOaQc4rA2nV7onMOZC6UvCG8LGFSZBnj1loDDL
# Wo/I+RuRok2j/Q4zcMnwkQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFHK1UmLCvXrQ
# CvR98JBq18/4zo0eMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQDju0quPbnix0sl
# EjD7j2224pYOPGTmdDvO0+bNRCNkZqUv07P04nf1If3Y/iJEmUaU7w12Fm582Imp
# D/Kw2ClXrNKLPTBO6nfxvOPGtalpAl4wqoGgZxvpxb2yEunG4yZQ6EQOpg1dE9uO
# Xoze3gD4Hjtcc75kca8yivowEI+rhXuVUWB7vog4TGUxKdnDvpk5GSGXnOhPDhdI
# d+g6hRyXdZiwgEa+q9M9Xctz4TGhDgOKFsYxFhXNJZo9KRuGq6evhtyNduYrkzjD
# tWS6gW8akR59UhuLGsVq+4AgqEY8WlXjQGM2OTkyBnlQLpB8qD7x9jRpY2Cq0OWW
# lK0wfH/1zefrWN5+be87Sw2TPcIudIJn39bbDG7awKMVYDHfsPJ8ZvxgWkZuf6ZZ
# Akph0eYGh3IV845taLkdLOCvw49Wxqha5Dmi2Ojh8Gja5v9kyY3KTFyX3T4C2scx
# fgp/6xRd+DGOhNVPvVPa/3yRUqY5s5UYpy8DnbppV7nQO2se3HvCSbrb+yPyeob1
# kUfMYa9fE2bEsoMbOaHRgGji8ZPt/Jd2bPfdQoBHcUOqPwjHBUIcSc7xdJZYjRb4
# m81qxjma3DLjuOFljMZTYovRiGvEML9xZj2pHRUyv+s5v7VGwcM6rjNYM4qzZQM6
# A2RGYJGU780GQG0QO98w+sucuTVrfTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKb
# SZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIy
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXI
# yjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjo
# YH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1y
# aa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v
# 3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pG
# ve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viS
# kR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYr
# bqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlM
# jgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSL
# W6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AF
# emzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIu
# rQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIE
# FgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
# 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
# MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2
# LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv
# 6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZn
# OlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1
# bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4
# rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU
# 6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDF
# NLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/
# HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdU
# CbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKi
# excdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTm
# dHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZq
# ELQdVTNYs6FwZvKhggNQMIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJp
# Y2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjg2MDMtMDVF
# MC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMK
# AQEwBwYFKw4DAhoDFQDTvVU/Yj9lUSyeDCaiJ2Da5hUiS6CBgzCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7JGqtDAi
# GA8yMDI1MTAwOTAzMjk1NloYDzIwMjUxMDEwMDMyOTU2WjB3MD0GCisGAQQBhFkK
# BAExLzAtMAoCBQDskaq0AgEAMAoCAQACAg40AgH/MAcCAQACAheJMAoCBQDskvw0
# AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSCh
# CjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAIvXvJsDaYPYpjK8HgvJq/Ro
# Y2M74oz34QdLpHWkVg+6+EBgFXsUTV//nE3U8zkhWXPpphlCx3wDd0V3FmeioWwz
# GFMGFpR9G2RjibZyXDq0aG/SwF2gF9eXuNQsc4yRe6dQWtjLqRl2NXcAIvOXun3n
# l/aX6Rwv9qsAoDIu8CFB/xF8Ox65oQC/GrdIvNKt+P8DkeLz67TAYwdI5xfxTkUd
# v5whearZ9Mqvpooq40Ox5uYqUYg47rzQg3Sd1RPSbBUVhEvPUlnSxU5ge8LqjKuE
# c8RNIgD8jhvafQkgBU63XLZEm6wYmh4b+bFsytmlWmenngtu3iuedX9epgzk9Qcx
# ggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AgcsETmJzYX7xQABAAACBzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDY3vk2tJcI/LGigKcmGDV+
# uYMQMbyWSvkZopeHMH9vWzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIC/3
# 1NHQds1IZ5sPnv59p+v6BjBDgoDPIwiAmn0PHqezMIGYMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIHLBE5ic2F+8UAAQAAAgcwIgQgUawV
# QU3tHmdqZU1zloE70njmoCuXkTUo8Asb57P5mAYwDQYJKoZIhvcNAQELBQAEggIA
# EE7MfGzO0Cy6bggEunDuuT8WAciwPX/bmc9bUldh1RZgcHCrHqoge6f+cWoeleBm
# 51p6JTAADjsZOPGu4n6pO5ZHWZn82Z7pet9Nzyf69xL2e7ZhbwAnN0yRjUj2v9t9
# R8/sq8woMgeKjbKnEseuVDZliVaXCVsKNuVwCHIrclrMsl7fPlgxzph9tY4K2upV
# vsWHdwFsQ0hbjF/n7NzgacvpNCB48OMNCELOQG4GhesYceePDbBdkuoz5+n/vwrH
# u8aSqNAEuEY/1cpXY1JcpCNUJK+U4iMAs5G5DGKV4uxurq6/NfFDinhILZT1V8+V
# Ygq3dswY2qfaxoq3FvGoUji6r/dRrj9WvLNLf0V7wcRoSA43HFhFKPpoMg3Gf2q3
# wW0bpTgQlHQ6BXQd2ARs3JYMKCwGvmJWDHpvbqyiBEZtF5hyd0rbFVBaFQWP7G6l
# EOPsFunQCtVXQ6NIewNKbZ5mpTrB6EYu93yfCLInZjn6vc6agqPBf4QYE/rguYOk
# bAMHSWsRqrRA9HL6pvsae7VKyXOnWQD2QzEjvTq1rUCCNoGOfNUMX16GKV1r5XHU
# dAnKqhgErnpzyoLYdsrtxZH0JNDiO+ZJQCf4AmPehhczyep1mcsXObYmOTdFor55
# OzwkKUYzR9F7wH3gXaXO63emx4omPde10qRzH+nbT5I=
# SIG # End signature block
