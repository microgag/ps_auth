<#
   ***Directory Services Authentication Scripts***

   Requires: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)

   Last Updated: 2025-10-09

   Version: 6.3
#>
#Requires -RunAsAdministrator

[cmdletbinding(PositionalBinding = $false, DefaultParameterSetName = "Default")]
param(
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$accepteula,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$vAuth,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$nonet,
    [Parameter(ParameterSetName = "WatchProcess")]
    [string]$watchProcess,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$whfb,
    [switch]$version,
    [switch]$persist,
    [switch]$slowlogon,
    [switch]$circular,
    [int]$etwsize = 0,
    [int]$netshsize = 1024)

[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')


# Collect parameters to pass to TSS_AUT.ps1 module
$AuthInputParams = @{
    vauth = $vAuth
    nonet = $nonet
    watchProcess = $watchProcess
    whfb = $whfb
    version = $version
    persist = $persist
    slowlogon = $slowlogon
    circular = $circular
    etwsize = $etwsize
    netshsize = $netshsize
}

#region --- EULA Definition ---

function ShowEULAPopup($mode) {
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12, 12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly = $True
    $richTextBox1.Add_LinkClicked({ Start-Process -FilePath $_.LinkText })
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::Yes })

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if ($mode -ne 0) {
        $btnCancel.Text = "Close"
    }
    else {
        $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::No })

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if ($mode -ne 0) {
        $EULA.AcceptButton = $btnCancel
    }
    else {
        $EULA.Controls.Add($btnAcknowledge)
        $EULA.AcceptButton = $btnAcknowledge
        $EULA.CancelButton = $btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode) {
    $eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
    $eulaAccepted = "No"
    $eulaValue = $toolName + " EULA Accepted"
    if (Test-Path $eulaRegPath) {
        $eulaRegKey = Get-Item $eulaRegPath
        $eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
    }
    else {
        $eulaRegKey = New-Item $eulaRegPath
    }
    if ($mode -eq 2) {
        # silent accept
        $eulaAccepted = "Yes"
        $ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
    }
    else {
        if ($eulaAccepted -eq "No") {
            $eulaAccepted = ShowEULAPopup($mode)
            if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes) {
                $eulaAccepted = "Yes"
                $ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
            }
        }
    }
    return $eulaAccepted
}

#endregion --- EULA Definition ---


$global:ScriptPrefix = 'auth'
$global:_BASE_LOG_DIR = ".\authlogs"
$global:_LOG_DIR = $_BASE_LOG_DIR

$global:ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType

# *** Create Directories ***
If ((Test-Path $_LOG_DIR) -eq "True") { Remove-Item -Path $_LOG_DIR -Force -Recurse }
New-Item -name $_LOG_DIR -ItemType Directory | Out-Null


function Start-Logman {
    param(
        [string]$TraceName,
        [string]$LogName,
        [bool]$Persist,
        [bool]$Circ,
        [int]$Size = 0
    )
    $ErrorActionPreference = "Stop"
    
    $prefixedTraceName = "auth_" + $TraceName

    if ($Persist) {
        # Make sure size was specified. Set to 4096MB if not.
        if (0 -eq $Size) {
            $Size = 4096
        }
        Push-Location $_LOG_DIR
        # Enforce circular logging for persistent tracing
        logman create trace "autosession\$prefixedTraceName" -ow -o "$LogName" -nb 16 16 -bs 1024 -mode Circular -f bincirc -max $Size -ets | Out-Null
        Pop-Location
    }
    elseif ($Circ) {
        # Make sure size was specified. Set to 1024MB if not.
        if (0 -eq $Size) {
            $Size = 1024
        }
        logman start "$prefixedTraceName" -ow -o "$_LOG_DIR\$LogName" -nb 16 16 -bs 1024 -mode Circular -f bincirc -max $Size -ets | Out-Null
    }
    else {
        if (0 -ne $Size) {
            logman start "$prefixedTraceName" -ow -o "$_LOG_DIR\$LogName" -nb 16 16 -bs 1024 -max $Size -ets #| Out-Null
        }
        else {
            logman start "$prefixedTraceName" -ow -o "$_LOG_DIR\$LogName" -nb 16 16 -bs 1024 -ets | Out-Null
        }
    }
}

function Update-Logman {
    param(
        [string]$TraceName,
        [string]$ProviderId,
        [string]$ProviderFlags,
        [string]$Options = "",
        [bool]$Persist
    )
    $prefixedTraceName = "auth_" + $TraceName

    if ($Persist) {
        # NOTE(will): Autologger will have it's path updated on EVERY logman update trace...
        Push-Location $_LOG_DIR
        logman update trace "autosession\$prefixedTraceName" -p "$ProviderId" $ProviderFlags 0xff -ets | Out-Null
        Pop-Location
    }
    else {
        logman update trace "$prefixedTraceName" -p "$ProviderId" $ProviderFlags 0xff -ets | Out-Null
    }
}


if ($version) {
    Write-Host $_Authscriptver
    return
}

if ($accepteula) {
    ShowEULAIfNeeded "DS Authentication Scripts:" 2
    "EULA Accepted"
}
else {
    $eulaAccepted = ShowEULAIfNeeded "DS Authentication Scripts:" 0
    if ($eulaAccepted -ne "Yes") {
        "EULA Declined"
        exit
    }
    "EULA Accepted"
}


# *** Set some system specifc variables ***
$global:wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
$global:osVersionString = $wmiOSObject.Version
$global:osBuildNumString = $wmiOSObject.BuildNumber

# *** Load TSS_AUT.psm1 module ***
$Scriptfolder = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
foreach($file in Get-ChildItem $Scriptfolder){
	$extension = [IO.Path]::GetExtension($file)
	if (($extension -eq ".psm1") -and ($file.Name -eq "TSS_AUT.psm1") ){
		$modName = ($file.Name).substring(0, ($file.Name).length - 5)
		$modPath = "$Scriptfolder\$($file.Name)"
		Remove-Module $modName -ErrorAction Ignore
		Import-Module $modPath -DisableNameChecking -ArgumentList @($null, $AuthInputParams)
	}
}

#region *** START ETL PROVIDER GROUPS ***

# Limit logman etw and netsh trace sizes to 8GB
if ($etwsize -gt 8192) {
    $etwsize = 8192
}
if ($netshsize -gt 8192) {
    $netshsize = 8192
}


# Start Logman NGC
$NGCSingleTraceName = "NGC"
Start-Logman -TraceName $NGCSingleTraceName -LogName "NGC.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($NGCProvider in $ADS_NGCProviders) {
    # Update Logman NGC
    $NGCParams = $NGCProvider.Split('!')
    $NGCSingleTraceGUID = $NGCParams[0]
    $NGCSingleTraceFlags = $NGCParams[2]

    Update-Logman -TraceName $NGCSingleTraceName -ProviderId $NGCSingleTraceGUID -ProviderFlags $NGCSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman Biometric
$BiometricSingleTraceName = "Biometric"
Start-Logman -TraceName $BiometricSingleTraceName -LogName "Biometric.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($BiometricProvider in $ADS_BioProviders) {
    # Update Logman Biometric
    $BiometricParams = $BiometricProvider.Split('!')
    $BiometricSingleTraceGUID = $BiometricParams[0]
    $BiometricSingleTraceFlags = $BiometricParams[2]

    Update-Logman -TraceName $BiometricSingleTraceName -ProviderId `"$BiometricSingleTraceGUID`" $BiometricSingleTraceFlags -Options "1:00 -rt" -Persist $persist.IsPresent
}


# Start Logman LSA
$LSASingleTraceName = "LSA"
Start-Logman -TraceName $LSASingleTraceName -LogName "LSA.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($LSAProvider in $ADS_LSAProviders) {
    # Update Logman LSA
    $LSAParams = $LSAProvider.Split('!')
    $LSASingleTraceGUID = $LSAParams[0]
    $LSASingleTraceFlags = $LSAParams[2]

    Update-Logman -TraceName $LSASingleTraceName -ProviderId "$LSASingleTraceGUID" -ProviderFlags $LSASingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman Ntlm_CredSSP
$Ntlm_CredSSPSingleTraceName = "Ntlm_CredSSP"
Start-Logman -TraceName $Ntlm_CredSSPSingleTraceName -LogName "Ntlm_CredSSP.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($Ntlm_CredSSPProvider in $ADS_NtLmCredSSPProviders) {
    # Update Logman Ntlm_CredSSP
    $Ntlm_CredSSPParams = $Ntlm_CredSSPProvider.Split('!')
    $Ntlm_CredSSPSingleTraceGUID = $Ntlm_CredSSPParams[0]
    $Ntlm_CredSSPSingleTraceFlags = $Ntlm_CredSSPParams[2]

    Update-Logman -TraceName $Ntlm_CredSSPSingleTraceName -ProviderId $Ntlm_CredSSPSingleTraceGUID -ProviderFlags $Ntlm_CredSSPSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman Kerberos
$KerberosSingleTraceName = "Kerberos"
Start-Logman -TraceName $KerberosSingleTraceName -LogName "Kerberos.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($KerberosProvider in $ADS_KerbProviders) {
    # Update Logman Kerberos
    $KerberosParams = $KerberosProvider.Split('!')
    $KerberosSingleTraceGUID = $KerberosParams[0]
    $KerberosSingleTraceFlags = $KerberosParams[2]

    Update-Logman -TraceName $KerberosSingleTraceName -ProviderId `"$KerberosSingleTraceGUID`" -ProviderFlags $KerberosSingleTraceFlags  -Persist $persist.IsPresent
}


# Start Logman KDC
if ($global:ProductType -eq "LanmanNT") {
    $KDCSingleTraceName = "KDC"
    Start-Logman -TraceName $KDCSingleTraceName -LogName "KDC.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

    ForEach ($KDCProvider in $ADS_KDCProviders) {
        # Update Logman KDC
        $KDCParams = $KDCProvider.Split('!')
        $KDCSingleTraceGUID = $KDCParams[0]
        $KDCSingleTraceFlags = $KDCParams[2]

        Update-Logman -TraceName $KDCSingleTraceName -ProviderId $KDCSingleTraceGUID -ProviderFlags $KDCSingleTraceFlags -Persist $persist.IsPresent
    }
}


# Start Logman SSL
$SSLSingleTraceName = "SSL"
Start-Logman -TraceName $SSLSingleTraceName -LogName "SSL.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($SSLProvider in $ADS_SSLProviders) {
    # Update Logman SSL
    $SSLParams = $SSLProvider.Split('!')
    $SSLSingleTraceGUID = $SSLParams[0]
    $SSLSingleTraceFlags = $SSLParams[2]

    Update-Logman -TraceName $SSLSingleTraceName -ProviderId $SSLSingleTraceGUID -ProviderFlags $SSLSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman WebAuth
$WebAuthSingleTraceName = "WebAuth"
Start-Logman -TraceName $WebAuthSingleTraceName -LogName "WebAuth.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($WebAuthProvider in $ADS_WebAuthProviders) {
    # Update Logman WebAuth
    $WebAuthParams = $WebAuthProvider.Split('!')
    $WebAuthSingleTraceGUID = $WebAuthParams[0]
    $WebAuthSingleTraceFlags = $WebAuthParams[2]

    Update-Logman -TraceName $WebAuthSingleTraceName -ProviderId $WebAuthSingleTraceGUID  -ProviderFlags $WebAuthSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman Smartcard
$SmartcardSingleTraceName = "Smartcard"
Start-Logman -TraceName $SmartcardSingleTraceName -LogName "Smartcard.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($SmartcardProvider in $ADS_SmartCardProviders) {
    # Update Logman Smartcard
    $SmartcardParams = $SmartcardProvider.Split('!')
    $SmartcardSingleTraceGUID = $SmartcardParams[0]
    $SmartcardSingleTraceFlags = $SmartcardParams[2]

    Update-Logman -TraceName $SmartcardSingleTraceName -ProviderId $SmartcardSingleTraceGUID -ProviderFlags $SmartcardSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman CredprovAuthui
$CredprovAuthuiSingleTraceName = "CredprovAuthui"
Start-Logman -TraceName $CredprovAuthuiSingleTraceName -LogName "CredprovAuthui.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($CredprovAuthuiProvider in $ADS_CredprovAuthuiProviders) {
    # Update Logman CredprovAuthui
    $CredprovAuthuiParams = $CredprovAuthuiProvider.Split('!')
    $CredprovAuthuiSingleTraceGUID = $CredprovAuthuiParams[0]
    $CredprovAuthuiSingleTraceFlags = $CredprovAuthuiParams[2]

    Update-Logman -TraceName $CredprovAuthuiSingleTraceName -ProviderId $CredprovAuthuiSingleTraceGUID -ProviderFlags $CredprovAuthuiSingleTraceFlags -Persist $persist.IsPresent
}

# Nonet check
if ($nonet.IsPresent -ne "False") {
    # Start Net Trace
    # Start and stop capture to ensure driver is loaded
    switch -regex ($osVersionString) {
        # Win7 has different args syntax.
        '^6\.1' { 
            netsh trace start capture=yes maxsize=1 report=no | Out-Null
            netsh trace stop | Out-Null
            netsh trace start capture=yes maxsize=$netshsize persistent=yes report=no tracefile=$_LOG_DIR\Nettrace.etl | Out-Null
        }

        default {
            netsh trace start capture=yes maxsize=1 report=disabled | Out-Null
            netsh trace stop | Out-Null
            if (($ProductType -eq "WinNT") -and ($vAuth)) {
                netsh trace start scenario=internetclient capture=yes maxsize=$netshsize persistent=yes report=disabled traceFile=$_LOG_DIR\Nettrace.etl | Out-Null
            }
            else {
                netsh trace start capture=yes maxsize=$netshsize persistent=yes report=disabled tracefile=$_LOG_DIR\Nettrace.etl | Out-Null
            }
        }
    }
}

# Start Logman CryptNcryptDpapi
if ($global:ProductType -eq "WinNT") {
    $CryptNcryptDpapiSingleTraceName = "CryptNcryptDpapi"
    Start-Logman -TraceName $CryptNcryptDpapiSingleTraceName -LogName "CryptNcryptDpapi.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

    ForEach ($CryptNcryptDpapiProvider in $ADS_CryptNcryptDpapiProviders) {
        # Update Logman CryptNcryptDpapi
        $CryptNcryptDpapiParams = $CryptNcryptDpapiProvider.Split('!')
        $CryptNcryptDpapiSingleTraceGUID = $CryptNcryptDpapiParams[0]
        $CryptNcryptDpapiSingleTraceFlags = $CryptNcryptDpapiParams[2]

        Update-Logman -TraceName $CryptNcryptDpapiSingleTraceName -ProviderId $CryptNcryptDpapiSingleTraceGUID  -ProviderFlags $CryptNcryptDpapiSingleTraceFlags -Persist $persist.IsPresent
    }
}
elseif ($vAuth) {
    $CryptNcryptDpapiSingleTraceName = "CryptNcryptDpapi"

    # Enforcing circular buffering
    Start-Logman -TraceName $CryptNcryptDpapiSingleTraceName -LogName "CryptNcryptDpapi.etl" -Persist $persist.IsPresent -Circ $true -Size $etwsize

    ForEach ($CryptNcryptDpapiProvider in $ADS_CryptNcryptDpapiProviders) {
        # Update Logman CryptNcryptDpapi
        $CryptNcryptDpapiParams = $CryptNcryptDpapiProvider.Split('!')
        $CryptNcryptDpapiSingleTraceGUID = $CryptNcryptDpapiParams[0]
        $CryptNcryptDpapiSingleTraceFlags = $CryptNcryptDpapiParams[2]

        Update-Logman -TraceName $CryptNcryptDpapiSingleTraceName -ProviderId $CryptNcryptDpapiSingleTraceGUID  -ProviderFlags $CryptNcryptDpapiSingleTraceFlags -Persist $persist.IsPresent
    }
}


# Start Logman SAM
$SAMSingleTraceName = "SAM"
Start-Logman -TraceName $SAMSingleTraceName -LogName "SAM.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($SAMProvider in $ADS_SAMsrvProviders) {
    # Update Logman SAM
    $SAMParams = $SAMProvider.Split('!')
    $SAMSingleTraceGUID = $SAMParams[0]
    $SAMSingleTraceFlags = $SAMParams[2]

    Update-Logman -TraceName $SAMSingleTraceName -ProviderId $SAMSingleTraceGUID -ProviderFlags $SAMSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman SSPICli
$SSPICliSingleTraceName = "SSPICli"
Start-Logman -TraceName $SSPICliSingleTraceName -LogName "SSPICli.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($SSPICliProvider in $ADS_SSPICli) {
    # Update Logman SSPICli
    $SSPICliParams = $SSPICliProvider.Split('!')
    $SSPICliSingleTraceGUID = $SSPICliParams[0]
    $SSPICliSingleTraceFlags = $SSPICliParams[2]

    Update-Logman -TraceName $SSPICliSingleTraceName -ProviderId $SSPICliSingleTraceGUID -ProviderFlags $SSPICliSingleTraceFlags -Persist $persist.IsPresent
}


# Start Logman KsecDD
$KsecDDSingleTraceName = "KsecDD"
Start-Logman -TraceName $KsecDDSingleTraceName -LogName "KsecDD.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

ForEach ($KsecDDProvider in $ADS_KsecDD) {
    # Update Logman KsecDD
    $KsecDDParams = $KsecDDProvider.Split('!')
    $KsecDDSingleTraceGUID = $KsecDDParams[0]
    $KsecDDSingleTraceFlags = $KsecDDParams[2]

    Update-Logman -TraceName $KsecDDSingleTraceName -ProviderId $KsecDDSingleTraceGUID -ProviderFlags $KsecDDSingleTraceFlags -Persist $persist.IsPresent
}


# **AppX** **Start Appx logman on clients, or in servers (except Domain Controllers) in case the '-v' switch is added**
if (($global:ProductType -eq "WinNT") -or (($vAuth) -and ($global:ProductType -ne "LanmanNT"))) {

    $AppxSingleTraceName = "AppX"
    Start-Logman -TraceName $AppxSingleTraceName -LogName "AppX.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

    ForEach ($AppXProvider in $ADS_AppxProviders) {
        # Update Logman Kerberos
        $AppXParams = $AppXProvider.Split('!')
        $AppXSingleTraceGUID = $AppXParams[0]
        $AppXSingleTraceFlags = $AppXParams[2]

        Update-Logman -TraceName $AppXSingleTraceName -ProviderId $AppXSingleTraceGUID -ProviderFlags $AppXSingleTraceFlags -Persist $persist.IsPresent
    }
}

# Start Logman GPSVC
if([version]$osVersionString -ge [version]"10.0.22621"){
    $GPSVCSingleTraceName = "GPSVC"
    Start-Logman -TraceName $GPSVCSingleTraceName -LogName "GPSVC.etl" -Persist $persist.IsPresent -Circ $circular.IsPresent -Size $etwsize

    ForEach ($GPSVCProvider in $ADS_GPSVC) {
        # Update Logman GPSVC
        $GPSVCParams = $GPSVCProvider.Split('!')
        $GPSVCSingleTraceGUID = $GPSVCParams[0]
        $GPSVCSingleTraceFlags = $GPSVCParams[2]

        Update-Logman -TraceName $GPSVCSingleTraceName -ProviderId $GPSVCSingleTraceGUID -ProviderFlags $GPSVCSingleTraceFlags -Persist $persist.IsPresent
    }
}

# Start Kernel logger
if ($global:ProductType -eq "WinNT") {
    $KernelSingleTraceName = "NT Kernel Logger"
    $KernelParams = $ADS_Kernel.Split('!')
    $KernelSingleTraceGUID = $KernelParams[0]
    $KernelSingleTraceFlags = $KernelParams[2]

    # NOTE(will): NT Kernel Logger doesn't support autosessions
    if ($persist.IsPresent -eq $false) {
        logman create trace $KernelSingleTraceName -ow -o $_LOG_DIR\kernel.etl -p `"$KernelSingleTraceGUID`" $KernelSingleTraceFlags 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets | Out-Null
    }
}

#endregion *** START ETL PROVIDER GROUPS ***

# *** ADS_AuthPreStart (Starts the data Collection) ***
ADS_AuthPreStart

# SIG # Begin signature block
# MIIoKgYJKoZIhvcNAQcCoIIoGzCCKBcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB/a4pUvuLJRqwS
# t1qDUbjmRk4St5D99dGID0H9famnW6CCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
# 7A5ZL83XAAAAAASFMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM3WhcNMjYwNjE3MTgyMTM3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDASkh1cpvuUqfbqxele7LCSHEamVNBfFE4uY1FkGsAdUF/vnjpE1dnAD9vMOqy
# 5ZO49ILhP4jiP/P2Pn9ao+5TDtKmcQ+pZdzbG7t43yRXJC3nXvTGQroodPi9USQi
# 9rI+0gwuXRKBII7L+k3kMkKLmFrsWUjzgXVCLYa6ZH7BCALAcJWZTwWPoiT4HpqQ
# hJcYLB7pfetAVCeBEVZD8itKQ6QA5/LQR+9X6dlSj4Vxta4JnpxvgSrkjXCz+tlJ
# 67ABZ551lw23RWU1uyfgCfEFhBfiyPR2WSjskPl9ap6qrf8fNQ1sGYun2p4JdXxe
# UAKf1hVa/3TQXjvPTiRXCnJPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUuCZyGiCuLYE0aU7j5TFqY05kko0w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwNTM1OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACjmqAp2Ci4sTHZci+qk
# tEAKsFk5HNVGKyWR2rFGXsd7cggZ04H5U4SV0fAL6fOE9dLvt4I7HBHLhpGdE5Uj
# Ly4NxLTG2bDAkeAVmxmd2uKWVGKym1aarDxXfv3GCN4mRX+Pn4c+py3S/6Kkt5eS
# DAIIsrzKw3Kh2SW1hCwXX/k1v4b+NH1Fjl+i/xPJspXCFuZB4aC5FLT5fgbRKqns
# WeAdn8DsrYQhT3QXLt6Nv3/dMzv7G/Cdpbdcoul8FYl+t3dmXM+SIClC3l2ae0wO
# lNrQ42yQEycuPU5OoqLT85jsZ7+4CaScfFINlO7l7Y7r/xauqHbSPQ1r3oIC+e71
# 5s2G3ClZa3y99aYx2lnXYe1srcrIx8NAXTViiypXVn9ZGmEkfNcfDiqGQwkml5z9
# nm3pWiBZ69adaBBbAFEjyJG4y0a76bel/4sDCVvaZzLM3TFbxVO9BQrjZRtbJZbk
# C3XArpLqZSfx53SuYdddxPX8pvcqFuEu8wcUeD05t9xNbJ4TtdAECJlEi0vvBxlm
# M5tzFXy2qZeqPMXHSQYqPgZ9jvScZ6NwznFD0+33kbzyhOSz/WuGbAu4cHZG8gKn
# lQVT4uA2Diex9DMs2WHiokNknYlLoUeWXW1QrJLpqO82TLyKTbBM/oZHAdIc0kzo
# STro9b3+vjn2809D0+SOOCVZMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGgowghoGAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE2YeM8T1FCDp2bNhPFi/x8W
# /+WUnckaDTYZyRafgYmlMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAJuGhymaDMVySQ1dDgiK27Evxe+tlAKqGrqgK3prmapQUgpKGfI+fKfk8
# mbbZFZDm1a6+sdts07JwPH8s/ndnzgmdnyVNF6HpWVJCwXZK9LQObteI/EAYEc61
# YZMtrNPBSboZQP8kULx9xYvLct6OWyQYDQ6w7HmxXtwlYZvfQR/DdWRlHfQ5K/Yu
# O4poVp8lwVnGEoluUG79b+9C4hdJ8ARXLyeXbZUTsmJEBNC7/isYpVdvLMStrEnL
# LX89DuUp0WSF34gVl3jGfUeNG1mk+pQZt+S/d3LbQ4uGhmfNKxZY4J6JsYpeaGh1
# rmqeOrj2NgjNFPNX/pI3t03HNmlRDqGCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCC
# F3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBPfD2sMKcgBCeXJBH47Ln6lA2HUp4y+XimaSp6htrS/QIGaNfLQ4Qt
# GBMyMDI1MTAwOTEyMTQxNS4zNjdaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHqMIIHIDCCBQigAwIBAgITMwAAAg9XmkcUQOZG5gABAAACDzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQz
# MDRaFw0yNjA0MjIxOTQzMDRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCl6DTurxf66o73G0A2yKo1/nYvITBQsd50F52SQzo2
# cSrt+EDEFCDlSxZzWJD7ujQ1Z1dMbMT6YhK7JUvwxQ+LkQXv2k/3v3xw8xJ2mhXu
# wbT+s1WOL0+9g9AOEAAM6WGjCzI/LZq3/tzHr56in/Z++o/2soGhyGhKMDwWl4J4
# L1Fn8ndtoM1SBibPdqmwmPXpB9QtaP+TCOC1vAaGQOdsqXQ8AdlK6Vuk9yW9ty7S
# 0kRP1nXkFseM33NzBu//ubaoJHb1ceYPZ4U4EOXBHi/2g09WRL9QWItHjPGJYjuJ
# 0ckyrOG1ksfAZWP+Bu8PXAq4s1Ba/h/nXhXAwuxThpvaFb4T0bOjYO/h2LPRbdDM
# cMfS9Zbhq10hXP6ZFHR0RRJ+rr5A8ID9l0UgoUu/gNvCqHCMowz97udo7eWODA7L
# aVv81FHHYw3X5DSTUqJ6pwP+/0lxatxajbSGsm267zqVNsuzUoF2FzPM+YUIwiOp
# gQvvjYIBkB+KUwZf2vRIPWmhAEzWZAGTox/0vj4eHgxwER9fpThcsbZGSxx0nL54
# Hz+L36KJyEVio+oJVvUxm75YEESaTh1RnL0Dls91sBw6mvKrO2O+NCbUtfx+cQXY
# S0JcWZef810BW9Bn/eIvow3Kcx0dVuqDfIWfW7imeTLAK9QAEk+oZCJzUUTvhh2h
# YQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFJnUMQ2OtyAhLR/MD2qtJ9lKRP9ZMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBTowbo1bUE7fXTy+uW9m58qGEXRBGVMEQi
# FEfSui1fhN7jS+kSiN0SR5Kl3AuV49xOxgHo9+GIne5Mpg5n4NS5PW8nWIWGj/8j
# kE3pdJZSvAZarXD4l43iMNxDhdBZqVCkAYcdFVZnxdy+25MRY6RfaGwkinjnYNFA
# 6DYL/1cxw6Ya4sXyV7FgPdMmxVpffnPEDFv4mcVx3jvPZod7gqiDcUHbyV1gaND3
# PejyJ1MGfBYbAQxsynLX1FUsWLwKsNPRJjynwlzBT/OQbxnzkjLibi4h4dOwcN+H
# 4myDtUSnYq9Xf4YvFlZ+mJs5Ytx4U9JVCyW/WERtIEieTvTRgvAYj/4Mh1F2Elf8
# cdILgzi9ezqYefxdsBD8Vix35yMC5LTnDUoyVVulUeeDAJY8+6YBbtXIty4phIki
# hiIHsyWVxW2YGG6A6UWenuwY6z9oBONvMHlqtD37ZyLn0h1kCkkp5kcIIhMtpzEc
# PkfqlkbDVogMoWy80xulxt64P4+1YIzkRht3zTO+jLONu1pmBt+8EUh7DVct/33t
# uW5NOSx56jXQ1TdOdFBpgcW8HvJii8smQ1TQP42HNIKIJY5aiMkK9M2HoxYrQy2M
# oHNOPySsOzr3le/4SDdX67uobGkUNerlJKzKpTR5ZU0SeNAu5oCyDb6gdtTiaN50
# lCC6m44sXjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNN
# MIICNQIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjMzMDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBe
# tIzj2C/MkdiI03EyNsCtSOMdWqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7JIZfTAiGA8yMDI1MTAwOTExMjIz
# N1oYDzIwMjUxMDEwMTEyMjM3WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDskhl9
# AgEAMAcCAQACAgWxMAcCAQACAhLrMAoCBQDsk2r9AgEAMDYGCisGAQQBhFkKBAIx
# KDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZI
# hvcNAQELBQADggEBAGQJwJJ/nRCEIFNFd3qnYjn9ryKFC+6Dd9eOayQxGr7RZOmW
# fK1JrsJT4UE2n19piUA1RvxEd/odzXYHACfnxOEmPIupe0lo/drK2B2o0rEg2vMD
# 2bID5xCXIAx+YZerBKunWrbhJS7xwgruaMYiZ1ozLIYZKPGfiifCLF89jGi9KX3a
# Yhje7FVlIDmMzPuUq4xOPZTu8Qc1VCGwGDi8C5cTeURAuyOHGjXY/UNgLxSwHkny
# keRBJp8kMKueMYOrG0CSkaWCUnK/RZvtiTfRkzOVzotCv06cDqd/kKY5a78mijzZ
# B9tft/Axe1VHQ3ahD67kpcIOWpnQ3PUVe4VAh1QxggQNMIIECQIBATCBkzB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAg9XmkcUQOZG5gABAAACDzAN
# BglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8G
# CSqGSIb3DQEJBDEiBCDbOEynMEGhK6nbOD89Bbs1a/bawej1K9pvhupW+qUY3DCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIN1Hd5UmKnm7FW7xP3niGsfHJt4x
# R8Xu+MxgXXc0iqn4MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAIPV5pHFEDmRuYAAQAAAg8wIgQg+9TdlXyqJ9IiwRp5fl6vcyHiaSwg
# dHpZdXnsu2KobakwDQYJKoZIhvcNAQELBQAEggIAczo9OUbi7OmZBdcqv6C1ljc8
# sQRmUH7Glc+PY3WqlDkkfvA0C+P6MXqC7YtRlCqrHiXArU0PdqWRa6jklPHUXA7y
# Z/6L3uyulP9fHS/lQR59EL1DYklU9iM4F6tXtbSqrN7TVapqq/tTDiGWva6Tvp9c
# MacSxhwV6OoSQIh0+SOf/twroFFOzaBvfQKw11dLi4pV6y12ElKteL17Uto3Lg2t
# lKM8AeiKla/rk5hVWqtaHY7r48yb3xflv8EGk3W1qf9XvlzYOQ5SVTpyQv+LXyCu
# ZQGwIRJ+DXTT0sYbg7b2nn6oJLDQ/xVJTdj+eYr67LrSnPkgaH+3DKuAWvDkY9NR
# NTgULdDzBpZormzLbdvvaLB6yw54vW+r/6AM4KSpyjlpxc//uc3HoLhG6IJ4hkoC
# KhJgXTt0s15d669rIf3ZW3qpUKuez7tdyGfCpCD2Mmc6K/y7FcHNF0FnIFEI60Lv
# VbaOv93bDAfIDgi/PSd1LURbM2qGBDddE/wAyZCmw58VsLvBmHPlUqtI3tmZH23l
# gmSbO9ErRr4kg6wIZHNaNUgIDsyDE9GBfqXWQwqUmP18cufnyGuztlzpfryUSqAO
# AqPy6Zo2TZmXLjTmrkOeuOp72xpo/R/bAbh4em0qNzn5Gk44e3YWmstKluZXXIuX
# cko/AMG/WB2kkbuo7hM=
# SIG # End signature block
