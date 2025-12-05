<#
.SYNOPSIS
	Auth module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
	Define ETW traces for Auth tracing
	Add any custom tracing functinaliy for tracing ADS components.


.NOTES  
	Dev. Lead: 
	Authors  : 
	Requires : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
	Version	 : 

.LINK
	TSS https://internal.evergreen.microsoft.com/en-us/help/4619187
	ADS https://internal.evergreen.microsoft.com/en-us/help/4619196
	
#>

param(
    [hashtable]$TSSInputParams,
    [hashtable]$AuthInputParams
)

# Collect TSS Input parameters
if ($global:ScriptPrefix -eq 'TSS'){
    $slowlogon = $TSSInputParams.slowlogon
    $vAuth = $TSSInputParams.vAuth
    $containerId = $TSSInputParams.containerId
	$whfb = $TSSInputParams.whfb
}

# Collect Auth Scripts Input parameters
if ($global:ScriptPrefix -eq 'auth'){
    $vAuth = $AuthInputParams.vAuth
    $nonet = $AuthInputParams.nonet
    $watchProcess = $AuthInputParams.watchProcess
    $whfb = $AuthInputParams.whfb
	$version = $AuthInputParams.version
    $persist = $AuthInputParams.persist
    $slowlogon = $AuthInputParams.slowlogon
    $circular = $AuthInputParams.circular
    $etwsize = $AuthInputParams.etwsize
    $netshsize = $AuthInputParams.netshsize    
}

$global:TssVerDateADS = "2025.10.09"
$global:TssVerDateAuth = "6.3"

#region --- ETW component trace Providers ---

# begining of auth providers

$ADS_AppxProviders = @(
	'{f0be35f8-237b-4814-86b5-ade51192e503}!Appx!0xffffffffffffffff'
	'{8127F6D4-59F9-4abf-8952-3E3A02073D5F}!Appx!0xffffffffffffffff'
	'{3ad13c53-cf84-4522-b349-56b81ffcd939}!Appx!0xffffffffffffffff'
	'{b89fa39d-0d71-41c6-ba55-effb40eb2098}!Appx!0xffffffffffffffff'
	'{fe762fb1-341a-4dd4-b399-be1868b3d918}!Appx!0xffffffffffffffff'
)

$ADS_BioProviders = @(
	'{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}!Bio!0xffff'
	'{225b3fed-0356-59d1-1f82-eed163299fa8}!Bio!0x0'
	'{9dadd79b-d556-53f2-67c4-129fa62b7512}!Bio!0x0'
	'{1B5106B1-7622-4740-AD81-D9C6EE74F124}!Bio!0x0'
	'{1d480c11-3870-4b19-9144-47a53cd973bd}!Bio!0x0'
	'{e60019f0-b378-42b6-a185-515914d3228c}!Bio!0x0'
	'{48CAFA6C-73AA-499C-BDD8-C0D36F84813E}!Bio!0x0'
	'{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}!Bio!0x0'
	'{e92355c0-41e4-4aed-8d67-df6b2058f090}!Bio!0x0'
	'{85be49ea-38f1-4547-a604-80060202fb27}!Bio!0x0'
	'{F4183A75-20D4-479B-967D-367DBF62A058}!Bio!0x0'
	'{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d}!Bio!0x0'
	'{39A5AA08-031D-4777-A32D-ED386BF03470}!Bio!0x0'
	'{22eb0808-0b6c-5cd4-5511-6a77e6e73a93}!Bio!0x0'
	'{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258}!Bio!0x0'
	'{9df19cfa-e122-5343-284b-f3945ccd65b2}!Bio!0x0'
	'{beb1a719-40d1-54e5-c207-232d48ac6dea}!Bio!0x0'
	'{8A89BB02-E559-57DC-A64B-C12234B7572F}!Bio!0x0'
	'{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}!Bio!0xffffffffffffffff'
)

$ADS_CredprovAuthuiProviders = @(
	'{5e85651d-3ff2-4733-b0a2-e83dfa96d757}!CredprovAuthui!0xffffffffffffffff'
	'{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD}!CredprovAuthui!0xffffffffffffffff'
	'{462a094c-fc89-4378-b250-de552c6872fd}!CredprovAuthui!0xffffffffffffffff'
	'{8db3086d-116f-5bed-cfd5-9afda80d28ea}!CredprovAuthui!0xffffffffffffffff'
	'{a55d5a23-1a5b-580a-2be5-d7188f43fae1}!CredprovAuthui!0xFFFF'
	'{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}!CredprovAuthui!0xFFFF'
	'{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0}!CredprovAuthui!0xffffffffffffffff'
	'{3EC987DD-90E6-5877-CCB7-F27CDF6A976B}!CredprovAuthui!0xffffffffffffffff'
	'{41AD72C3-469E-5FCF-CACF-E3D278856C08}!CredprovAuthui!0xffffffffffffffff'
	'{4F7C073A-65BF-5045-7651-CC53BB272DB5}!CredprovAuthui!0xffffffffffffffff'
	'{A6C5C84D-C025-5997-0D82-E608D1ABBBEE}!CredprovAuthui!0xffffffffffffffff'
	'{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74}!CredprovAuthui!0xffffffffffffffff'
	'{DF350158-0F8F-555D-7E4F-F1151ED14299}!CredprovAuthui!0xffffffffffffffff'
	'{FB3CD94D-95EF-5A73-B35C-6C78451095EF}!CredprovAuthui!0xffffffffffffffff'
	'{d451642c-63a6-11d7-9720-00b0d03e0347}!CredprovAuthui!0xffffffffffffffff'
	'{b39b8cea-eaaa-5a74-5794-4948e222c663}!CredprovAuthui!0xffffffffffffffff'
	if(!$slowlogon){'{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}!CredprovAuthui!0xffffffffffffffff'}
	'{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}!CredprovAuthui!0xffffffffffffffff'
	'{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}!CredprovAuthui!0xffffffffffffffff'
	'{a789efeb-fc8a-4c55-8301-c2d443b933c0}!CredprovAuthui!0xffffffffffffffff'
	'{301779e2-227d-4faf-ad44-664501302d03}!CredprovAuthui!0xffffffffffffffff'
	'{557D257B-180E-4AAE-8F06-86C4E46E9D00}!CredprovAuthui!0xffffffffffffffff'
	'{D33E545F-59C3-423F-9051-6DC4983393A8}!CredprovAuthui!0xffffffffffffffff'
	'{19D78D7D-476C-47B6-A484-285D1290A1F3}!CredprovAuthui!0xffffffffffffffff'
	'{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!CredprovAuthui!0xffffffffffffffff'
	'{D9391D66-EE23-4568-B3FE-876580B31530}!CredprovAuthui!0xffffffffffffffff'
	'{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}!CredprovAuthui!0xffffffffffffffff'
	'{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!CredprovAuthui!0xffffffffffffffff'
	'{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!CredprovAuthui!0xffffffffffffffff'
	'{5A24FCDB-1CF3-477B-B422-EF4909D51223}!CredprovAuthui!0xffffffffffffffff'
	'{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!CredprovAuthui!0xffffffffffffffff'
	'{4B812E8E-9DFC-56FC-2DD2-68B683917260}!CredprovAuthui!0xffffffffffffffff'
	'{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!CredprovAuthui!0xffffffffffffffff'
	'{041afd1b-de76-48e9-8b5c-fade631b0dd5}!CredprovAuthui!0xffffffffffffffff'
	'{39568446-adc1-48ec-8008-86c11637fc74}!CredprovAuthui!0xffffffffffffffff'
	'{d1731de9-f885-4e1f-948b-76d52702ede9}!CredprovAuthui!0xffffffffffffffff'
	'{d5272302-4e7c-45be-961c-62e1280a13db}!CredprovAuthui!0xffffffffffffffff'
	'{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!CredprovAuthui!0xffffffffffffffff'
	'{ba634d53-0db8-55c4-d406-5c57a9dd0264}!CredprovAuthui!0xffffffffffffffff' # New intune PasswordlessPolicy GUID
)

$ADS_CryptNcryptDpapiProviders = @(
	'{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473302}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473301}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473303}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473305}!CryptNcryptDpapi!0xFFFFFFFF'
	'{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}!CryptNcryptDpapi!0x0'
	'{a74efe00-14be-4ef9-9da9-1484d5473304}!CryptNcryptDpapi!0xffffffffffffffff'
	'{9d2a53b2-1411-5c1c-d88c-f2bf057645bb}!CryptNcryptDpapi!0xffffffffffffffff'
)

$ADS_KDCProviders = @(
	'{1BBA8B19-7F31-43c0-9643-6E911F79A06B}!kdc!0xfffff'
	'{f2c3d846-1d17-5388-62fa-3839e9c67c80}!kdc!0xffffffffffffffff'
	'{6C51FAD2-BA7C-49b8-BF53-E60085C13D92}!kdc!0xffffffffffffffff'
)

$ADS_KerbProviders = @(
	'{6B510852-3583-4e2d-AFFE-A67F9F223438}!Kerb!0x7ffffff'
	'{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!Kerb!0xffffff'
	'{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!Kerb!0xffffffff'
	'{97A38277-13C0-4394-A0B2-2A70B465D64F}!Kerb!0xff'
	'{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!Kerb!0xffffffffffffffff'
	'{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!Kerb!0xffffffffffffffff'
    '{1eac4041-7c1c-41d3-a617-87851875f630}!Kerb!0xffffffffffffffff'    # New not yet in market Kerb3961 GUID
)

$ADS_LSAProviders = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'               # (WPP)LsaTraceControlGuid
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'               # LsaDs
	'{DAA76F6A-2D11-4399-A646-1D62B7380F15}!lsa!0xffffff'               # (WPP)LsaAuditTraceControlGuid
	'{366B218A-A5AA-4096-8131-0BDAFCC90E93}!lsa!0xfffffff'              # (WPP)LsaIsoTraceControlGuid
	'{4D9DFB91-4337-465A-A8B5-05A27D930D48}!lsa!0xff'                   # (TL)Microsoft.Windows.Security.LsaSrv
	'{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!lsa!0xFFF'                  # (WPP)VaultGlobalDebugTraceControlGuid
	'{CA030134-54CD-4130-9177-DAE76A3C5791}!lsa!0xfffffff'              # (WPP)NETLOGON
	'{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!lsa!0xffffffffffffffff'     # (WPP)VaultCDSTraceGuid
	'{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!lsa!0xffffffffffffffff'     # (WPP)GmsaClientTraceControlGuid
	'{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!lsa!0xffffffffffffffff'     # (WPP)CCGLaunchPadTraceControlGuid
	'{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!lsa!0xffffffffffffffff'     # (WPP)CCGTraceControlGuid
	'{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!lsa!0xffffffffffffffff'
	'{ba634d53-0db8-55c4-d406-5c57a9dd0264}!lsa!0xffffffffffffffff'     # (TL)Microsoft.Windows.Security.PasswordlessPolicy
	'{45E7DBC5-E130-5CEF-9353-CC5EBF05E6C8}!lsa!0xFFFF'                 # (EVT)Microsoft-Windows-Containers-CCG/Admin
	'{A4E69072-8572-4669-96B7-8DB1520FC93A}!lsa!0xffffffffffffffff'
	'{C5D12E1B-84A0-4fe6-9E5F-FEBA123EAE66}!lsa!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
	'{E2E66F29-4D71-4646-8E58-20E204C3C25B}!lsa!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
	'{6f2c1ee5-1dfd-519b-2d55-702756f5964d}!lsa!0xffffffffffffffff'
	'{FB093D76-8964-11DF-9EA1-CB38E0D72085}!lsa!0xFFFF'                 # (WPP)KDSSVCCtlGuid
	'{3353A14D-EE30-436E-8FF5-575A4351EA80}!lsa!0xFFFF'                 # (WPP)KDSPROVCtlGuid
	'{afda4fd8-2fe5-5c75-ba0e-7d5c0b225e12}!lsa!0xffffffffffffffff'
	'{cbb61b6d-a2cf-471a-9a58-a4cd5c08ffba}!lsa!0xff'                   # (WPP)UACLog
)

$ADS_NGCProviders = @(  
	'{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KspSvc
	'{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CredProv
	'{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CryptNgc
	'{0ABA6892-455B-551D-7DA8-3A8F85225E1A}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnr
	'{9DF6A82D-5174-5EBF-842A-39947C48BF2A}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnrSvc
	'{9B223F67-67A1-5B53-9126-4593FE81DF25}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KeyStaging
	'{89F392FF-EE7C-56A3-3F61-2D5B31A36935}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CSP
	'{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}!ngc!0x0'                # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}!ngc!0xffff'             # Microsoft-Windows-Security-NGC-PopKeySrv
	'{CDC6BEB9-6D78-5138-D232-D951916AB98F}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcIsoCtnr
	'{C0B2937D-E634-56A2-1451-7D678AA3BC53}!ngc!0x0'                # Microsoft.Windows.Security.Ngc.Truslet
	'{9D4CA978-8A14-545E-C047-A45991F0E92F}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Recovery
	'{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Local
	'{34646397-1635-5d14-4d2c-2febdcccf5e9}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KeyCredMgr
	'{c12f629d-37d4-58f7-22a8-94ac45ad8648}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Utils
	'{3A8D6942-B034-48e2-B314-F69C2B4655A3}!ngc!0xffffffff'         # TPM
	'{5AA9A3A3-97D1-472B-966B-EFE700467603}!ngc!0xffffffff'         # TPM Virtual Smartcard card simulator
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}!ngc!0xffffffff'         # Cryptographic TPM Endorsement Key Services

	'{23B8D46B-67DD-40A3-B636-D43E50552C6D}!ngc!0x0'                # Microsoft-Windows-User Device Registration (event)

	'{2056054C-97A6-5AE4-B181-38BC6B58007E}!ngc!0x0'                # Microsoft.Windows.Security.DeviceLock

	'{7955d36a-450b-5e2a-a079-95876bca450a}!ngc!0x0'                # Microsoft.Windows.Security.DevCredProv
	'{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}!ngc!0x0'                # Microsoft.Windows.Security.DevCredSvc
	'{78983c7d-917f-58da-e8d4-f393decf4ec0}!ngc!0x0'                # Microsoft.Windows.Security.DevCredClient
	'{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}!ngc!0x0'                # Microsoft.Windows.Security.DevCredWinRt
	'{86D5FE65-0564-4618-B90B-E146049DEBF4}!ngc!0x0'                # Microsoft.Windows.Security.DevCredTask

	'{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}!ngc!0x0'                # MDM SCEP Trace
	'{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}!ngc!0x0'                # Microsoft-Windows-DM-Enrollment-Provider (event)
	'{3DA494E4-0FE2-415C-B895-FB5265C5C83B}!ngc!0x0'                # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider (event)

	'{73370BD6-85E5-430B-B60A-FEA1285808A7}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient (event)
	'{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-AutoEnrollment (event)
	'{54164045-7C50-4905-963F-E5BC1EEF0CCA}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-CertEnroll (event)
	'{89A2278B-C662-4AFF-A06C-46AD3F220BCA}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-CredentialRoaming (event)
	'{BC0669E1-A10D-4A78-834E-1CA3C806C93B}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-System (event)
	'{BEA18B89-126F-4155-9EE4-D36038B02680}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-User (event)
	'{B2D1F576-2E85-4489-B504-1861C40544B3}!ngc!0x0'                # Microsoft-Windows-CertificateServices-Deployment (event)
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!ngc!0x0'                # Microsoft-Windows-CertificationAuthorityClient-CertCli (event)
	'{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}!ngc!0x0'                # Microsoft-Windows-CertPolEng (event)

	'{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}!ngc!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost
	'{99eb7b56-f3c6-558c-b9f6-09a33abb4c83}!ngc!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost.Common
	'{aa02d1a4-72d8-5f50-d425-7402ea09253a}!ngc!0x0'                # Microsoft.Windows.Shell.CloudDomainJoin.Client
	'{507C53AE-AF42-5938-AEDE-4A9D908640ED}!ngc!0x0'                # Microsoft.Windows.Security.Credentials.UserConsentVerifier

	'{02ad713f-20d4-414f-89d0-da5a6f3470a9}!ngc!0xffffffffffffffff' # Microsoft.Windows.Security.CFL.API
	'{acc49822-f0b2-49ff-bff2-1092384822b6}!ngc!0xffffffffffffffff' # Microsoft.CAndE.ADFabric.CDJ
	'{f245121c-b6d1-5f8a-ea55-498504b7379e}!ngc!0xffffffffffffffff' # Microsoft.Windows.DeviceLockSettings
)
# **NGC** **Add additional NGC providers in case it's a client and the '-vAuth' switch is added**
if ($vAuth) {
	if ($ProductType -eq "WinNT") {
		$ADS_NGCProviders = $ADS_NGCProviders + @(
			'{6ad52b32-d609-4be9-ae07-ce8dae937e39}!ngc!0xffffffffffffffff'	 # Microsoft-Windows-RPC
			'{f4aed7c7-a898-4627-b053-44a7caa12fcd}!ngc!0xffffffffffffffff'	 # Microsoft-Windows-RPC-Events
			'{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871}!ngc!0xffffffffffffffff'	 # Microsoft.Windows.Application.Service
		)
	}
}

$ADS_NtLmCredSSPProviders = @(
	'{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!NtLmCredssp!0x5ffDf'			# Security: NTLM Authentication
	'{AC69AE5B-5B21-405F-8266-4424944A43E9}!NtLmCredssp!0xffffffff'			# NtlmSharedDebugTraceControlGuid
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!NtLmCredssp!0xffffffff'			# Security: TSPkg
	'{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!NtLmCredssp!0xffffffffffffffff'	# Microsoft-Windows-NTLM
	'{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!NtLmCredssp!0xffffffffffffffff'	# TSClientActiveXControlTrace
)

$ADS_SAMsrvProviders = @(
	'{8E598056-8993-11D2-819E-0000F875A064}!Sam!0xffffffffffffffff'
	'{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}!Sam!0xffffffffffffffff'
	'{BD8FEA17-5549-4B49-AA03-1981D16396A9}!Sam!0xffffffffffffffff'
	'{F2969C49-B484-4485-B3B0-B908DA73CEBB}!Sam!0xffffffffffffffff'
	'{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}!Sam!0xffffffffffffffff'
)

$ADS_SmartCardProviders = @(
	'{30EAE751-411F-414C-988B-A8BFA8913F49}!SmartCard!0xffffffffffffffff'
	'{13038E47-FFEC-425D-BC69-5707708075FE}!SmartCard!0xffffffffffffffff'
	'{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01}!SmartCard!0xffffffffffffffff'
	'{FB36CAF4-582B-4604-8841-9263574C4F2C}!SmartCard!0xffffffffffffffff'
	'{133A980D-035D-4E2D-B250-94577AD8FCED}!SmartCard!0xffffffffffffffff'
	'{EED7F3C9-62BA-400E-A001-658869DF9A91}!SmartCard!0xffffffffffffffff'
	'{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F}!SmartCard!0xffffffffffffffff'
	'{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465}!SmartCard!0xffffffffffffffff'
	'{31332297-E093-4B25-A489-BC9194116265}!SmartCard!0xffffffffffffffff'
	'{4fcbf664-a33a-4652-b436-9d558983d955}!SmartCard!0xffffffffffffffff'
	'{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480}!SmartCard!0xffffffffffffffff'
	'{125f2cf1-2768-4d33-976e-527137d080f8}!SmartCard!0xffffffffffffffff'
	'{beffb691-61cc-4879-9cd9-ede744f6d618}!SmartCard!0xffffffffffffffff'
	'{545c1f45-614a-4c72-93a0-9535ac05c554}!SmartCard!0xffffffffffffffff'
	'{AEDD909F-41C6-401A-9E41-DFC33006AF5D}!SmartCard!0xffffffffffffffff'
	'{09AC07B9-6AC9-43BC-A50F-58419A797C69}!SmartCard!0xffffffffffffffff'
	'{AAEAC398-3028-487C-9586-44EACAD03637}!SmartCard!0xffffffffffffffff'
	'{9F650C63-9409-453C-A652-83D7185A2E83}!SmartCard!0xffffffffffffffff'
	'{F5DBD783-410E-441C-BD12-7AFB63C22DA2}!SmartCard!0xffffffffffffffff'
	'{a3c09ba3-2f62-4be5-a50f-8278a646ac9d}!SmartCard!0xffffffffffffffff'
	'{15f92702-230e-4d49-9267-8e25ae03047c}!SmartCard!0xffffffffffffffff'
	'{179f04fd-cf7a-41a6-9587-a3d22d5e39b0}!SmartCard!0xffffffffffffffff'
)

$ADS_SSLProviders = @(  # this is more than in auth scripts
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}!Ssl!0xffffffffffffffff!0xff' # Ssl / Microsoft-Windows-CAPI2 - see Git #894, changed Level from 0x4000ffff to 0x7fffffff to 0xffffffffffffffff
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473304}!NcryptSslp!0x7fffffff!0xff' # NcryptSslp
	'{1F678132-5938-4686-9FDC-C8FF68F15C85}!Schannel'					# Schannel
	'{91CC1150-71AA-47E2-AE18-C96E61736B6F}!Schannel'					# Microsoft-Windows-Schannel-Events	
	'{44492B72-A8E2-4F20-B0AE-F1D437657C92}!Schannel'					# Microsoft.Windows.Security.Schannel	
)

$ADS_KsecDD = @(
	'{cceca73a-8b2e-4de5-877c-8b58e16008f8}!KsecDD!0xffffffffffffffff'
)

$ADS_SSPICli = @(
	'{ce603977-86cc-41d4-8834-7bf7022f49ef}!SSPICli!0xffffffffffffffff'
)

$ADS_WebAuthProviders = @(
	'{B1108F75-3252-4b66-9239-80FD47E06494}!WebAuth!0x2FF'                  #IDCommon
	'{82c7d3df-434d-44fc-a7cc-453a8075144e}!WebAuth!0x2FF'                  #IdStoreLib
	'{D93FE84A-795E-4608-80EC-CE29A96C8658}!WebAuth!0x7FFFFFFF'             #idlisten

	'{EC3CA551-21E9-47D0-9742-1195429831BB}!WebAuth!0xFFFFFFFF'             #cloudap
	'{bb8dd8e5-3650-5ca7-4fea-46f75f152414}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp
	'{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp.Critical

	'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker
	'{7acf487e-104b-533e-f68a-a7e9b0431edb}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker.BrowserSSO
	'{5836994d-a677-53e7-1389-588ad1420cc5}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.MicrosoftAccount.TBProvider

	'{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5}!WebAuth!0x7'                    #wlidsvc
	'{C10B942D-AE1B-4786-BC66-052E5B4BE40E}!WebAuth!0x3FF'                  #livessp
	'{05f02597-fe85-4e67-8542-69567ab8fd4f}!WebAuth!0xffffffffffffffff'     #Microsoft-Windows-LiveId, MSAClientTraceLoggingProvider

	'{74D91EC4-4680-40D2-A213-45E2D2B95F50}!WebAuth!0xFFFFFFFF'             #Microsoft.AAD.CloudAp.Provider
	'{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-AAD
	'{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}!WebAuth!0xFFFFFFFF'             #AADPlugin
	'{556045FD-58C5-4A97-9881-B121F68B79C5}!WebAuth!0xFFFFFFFF'             #AadCloudAPPlugin
	'{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0}!WebAuth!0xFFFFFFFF'             #AadWamExtension
	'{9EBB3B15-B094-41B1-A3B8-0F141B06BADD}!WebAuth!0xFFF'                  #AadAuthHelper
	'{6ae51639-98eb-4c04-9b88-9b313abe700f}!WebAuth!0xFFFFFFFF'             #AadWamPlugin
	'{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2}!WebAuth!0xFFFFFFFF'             #AadTB
	'{86510A0A-FDF4-44FC-B42F-50DD7D77D10D}!WebAuth!0xFFFFFFFF'             #AadBrokerPluginApp
	'{5A9ED43F-5126-4596-9034-1DCFEF15CD11}!WebAuth!0xFFFFFFFF'             #AadCloudAPPluginBVTs

	'{08B15CE7-C9FF-5E64-0D16-66589573C50F}!WebAuth!0xFFFFFF7F'             #Microsoft.Windows.Security.Fido

	'{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B}!WebAuth!0xFFFF'                 #negoexts
	'{2A6FAF47-5449-4805-89A3-A504F3E221A6}!WebAuth!0xFFFF'                 #pku2u

	'{EF98103D-8D3A-4BEF-9DF2-2156563E64FA}!WebAuth!0xFFFF'                 #webauth
	'{2A3C6602-411E-4DC6-B138-EA19D64F5BBA}!WebAuth!0xFFFF'                 #webplatform

	'{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD}!WebAuth!0x000003FF'             #wdigest

	'{2745a526-23f5-4ef1-b1eb-db8932d43330}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.TrustedSignal
	'{c632d944-dddb-599f-a131-baf37bf22ef0}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.Service

	'{63b6c2d2-0440-44de-a674-aa51a251b123}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.BrokerInfrastructure
	'{4180c4f7-e238-5519-338f-ec214f0b49aa}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.ResourceManager
	'{EB65A492-86C0-406A-BACE-9912D595BD69}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-AppModel-Exec
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-ProcessStateManager
	'{072665fb-8953-5a85-931d-d06aeab3d109}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.ProcessLifetimeManager
	'{EF00584A-2655-462C-BC24-E7DE630E7FBF}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.AppLifeCycle
	'{d48533a7-98e4-566d-4956-12474e32a680}!WebAuth!0xffffffffffffffff'     #RuntimeBrokerActivations
	'{0b618b2b-0310-431e-be64-09f4b3e3e6da}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.wpp
)

# **GPSVC** **Only add if it's NI or above
if(([version]$osVersionString -ge [version]"10.0.22621") -or ($global:OSVersion.Build -ge 22621)) {
	$ADS_GPSVC = @(
		'{80d25b7f-facc-5141-9929-c0e6eb5e96c5}!GPSVC!0xffffffffffffffff'
	)
}

# **WebAuth** **Add additional WebAuth providers in case it's a client and the -vAuth switch is added**
if ($vAuth) {
	if ($ProductType -eq "WinNT") {
		$ADS_WebAuthProviders = $ADS_WebAuthProviders + @(
			'{20f61733-57f1-4127-9f48-4ab7a9308ae2}!WebAuth!0xffffffffffffffff'
			'{b3a7698a-0c45-44da-b73d-e181c9b5c8e6}!WebAuth!0xffffffffffffffff'
			'{4e749B6A-667D-4C72-80EF-373EE3246B08}!WebAuth!0xffffffffffffffff'
			'{E16EC3D2-BB0F-4E8F-BDB8-DE0BEA82DC3D}!WebAuth!0x3F0000054404'
		)
	}
}

if ($global:ScriptPrefix -eq 'auth') {
    $ADS_Kernel = @(
    '{9E814AAD-3204-11D2-9A82-006008A86939}!kernel!0x0000000000000005'
    )
}

# trace definition
$ADS_AuthProviders = @(
	$ADS_AppxProviders
	$ADS_BioProviders
	$ADS_CredprovAuthuiProviders
	$ADS_CryptNcryptDpapiProviders
	$ADS_KerbProviders
	$ADS_LSAProviders
	$ADS_NGCProviders
	$ADS_NtLmCredSSPProviders
	$ADS_SAMsrvProviders
	$ADS_SmartCardProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
    $ADS_SSPICli
	$ADS_KsecDD
	if(([version]$osVersionString -ge [version]"10.0.22621") -or ($global:OSVersion.Build -ge 22621)) {
		$ADS_GPSVC
	}
 )

if ($global:ProductType -eq "LanmanNT") {
	$ADS_AuthProviders += $ADS_KDCProviders	#only for KDC/LanmanNT
}
if ($global:ScriptPrefix -eq 'auth') {
    $ADS_AuthProviders+=$ADS_Kernel
}

#endregion --- ETW component trace Providers ---


#region ### Pre-Start (ADS_AuthPreStart called by start-auth.ps1) / Post-Stop (CollectADS_AuthLog called by stop-auth.ps1) / Collect functions for trace components and scenarios 

# -------------- ADSAUTH ---------------

function ADS_AuthPreStart{
	[float]$_Authscriptver = "6" # add/update this also in TSS FW
	$_WatchProcess = $null
    if ($global:ScriptPrefix -eq 'TSS'){
	        $_BASE_LOG_DIR = $global:LogFolder #".\authlogs"
            $_LOG_DIR = $_BASE_LOG_DIR
            }
    elseif ($global:ScriptPrefix -eq 'auth') {
        $_BASE_LOG_DIR = $global:_BASE_LOG_DIR
        $_LOG_DIR = $global:_LOG_DIR
        $_ScriptStartedMsg = "`n
        ===== Microsoft CSS Authentication Scripts started tracing =====`n
        The tracing has now started.
        Once you have created the issue or reproduced the scenario, please run stop-auth.ps1 from this same directory to stop the tracing.`n"
        }

   
    # *** Set some system specifc variables ***
	$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
	$osVersionString = $wmiOSObject.Version
	$osBuildNumString = $wmiOSObject.BuildNumber

	$_PRETRACE_LOG_DIR = $_LOG_DIR + "\PreTraceLogs"
	$_WHFB_LOG_DIR = $_LOG_DIR + "\WHFB"
	
	New-Item -Path $_PRETRACE_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_WHFB_LOG_DIR -ItemType Directory | Out-Null
    
    # *** Disclaimer ***
    if ($global:ScriptPrefix -eq 'auth') {
        Write-Host "`n
***************** Microsoft CSS Authentication Scripts ****************`n
This Data collection is for Authentication, smart card and Credential provider scenarios`n
Data is collected into a subdirectory of the directory from where this script is launched, called ""Authlogs"".`n
*************************** IMPORTANT NOTICE **************************`n
The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.`n

You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"

        Write-Host "`nPlease wait whilst the tracing starts.....`n"

        # *** Check for PowerShell version ***
        $PsVersion = ($PSVersionTable).PSVersion.ToString()

        if ($psversiontable.psversion.Major -lt "4") {
            Write-Host
            "============= Microsoft CSS Authentication Scripts =============`n
        The script requires PowerShell version 4.0 or above to run.`n
        Version detected is $PsVersion`n
        Stopping script`n"
            exit
        }
    }
    
    
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


    # **WPR Check** ** Checks if WPR is installed in case OS < Win10 and 'slowlogon' switch is added**
    if ($slowlogon) {

        [version]$OSVersion = (Get-CimInstance Win32_OperatingSystem).version
        if (!($OSVersion -gt [version]'10.0')) {
            try {
                Start-Process -FilePath wpr -WindowStyle Hidden -ErrorVariable WPRnotInstalled;
            }
            catch {
                if ($WPRnotInstalled) {
                    Write-Host "`nWarning!" -ForegroundColor Yellow
                    write-host "Windows Performance Recorder (WPR) needs to be installed before the '-slowlogon' switch can be used.`n" -ForegroundColor Yellow
                    Write-host "You can download Windows Performance Recorder here: https://go.microsoft.com/fwlink/p/?LinkId=526740" -ForegroundColor Yellow
                    Write-host "Exiting script.`n" -ForegroundColor Yellow
                    exit;
                }
            }
        }
    }

        
    # *** Check if script is running ***
    If ((Test-Path $_BASE_LOG_DIR\started.txt) -eq "True") {
        Write-Host "
===== Microsoft CSS Authentication Scripts started tracing =====

We have detected that tracing has already been started.
Please run stop-auth.ps1 to stop the tracing.`n"
        exit
    }
    
    if ($null -ne $watchProcess -and "" -ne $watchProcess) {
        # Try by name
        $_WatchProcess = Get-Process $watchProcess -ErrorAction "SilentlyContinue"
        
        if ($null -eq $_WatchProcess) {
            # Try as process id
            try {
                $_WatchProcess = Get-Process -Id $watchProcess -ErrorAction "SilentlyContinue"
            }
            catch {
                # NOP
            }
        }
        if ($null -eq $_WatchProcess) {
            Write-Error "Failed to find Process $watchProcess"
            return
        }
        if ($_WatchProcess.Count -gt 1) {
            Write-Error "Multiple instances of $watchProcess found. Please use Process Id instead"
            return
        }
    }

  
	Add-Content -Path $_LOG_DIR\script-info.txt -Value "Microsoft CSS Authentication Script version $_Authscriptver"
	Add-Content -Path $_LOG_DIR\started.txt -Value "Started"

    
    # **slowlogon** ** Generate customer WPRP**
	if ($slowlogon) {
	function Generate-slowlogonWPRP{	
	
	$sbsl_wprp_file = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0"  Author="Auth Scripts Team">
  <Profiles>
	<SystemCollector Id="SBSL_System_Collector" Name="SBSL System Collector">
	  <BufferSize Value="1024" />
	  <Buffers Value="3276" />
	</SystemCollector>
	<EventCollector Id="SBSL_Event_Collector" Name="SBSL Event Collector">
	  <BufferSize Value="1024" />
	  <Buffers Value="655" />
	</EventCollector>
	<SystemProvider Id="SBSL_Collector_Provider">
	  <Keywords>	
		<Keyword Value="CpuConfig" />
		<Keyword Value="CSwitch" />
		<Keyword Value="DiskIO" />
		<Keyword Value="DPC" />
		<Keyword Value="Handle" />
		<Keyword Value="HardFaults" />
		<Keyword Value="Interrupt" />
		<Keyword Value="Loader" />
		<Keyword Value="MemoryInfo" />
		<Keyword Value="MemoryInfoWS" />
		<Keyword Value="ProcessCounter" />
		<Keyword Value="Power" />
		<Keyword Value="ProcessThread" />
		<Keyword Value="ReadyThread" />
		<Keyword Value="SampledProfile" />
		<Keyword Value="ThreadPriority" />
		<Keyword Value="VirtualAllocation" />
		<Keyword Value="WDFDPC" />
		<Keyword Value="WDFInterrupt" />
	  </Keywords>
	  <Stacks>
		<Stack Value="CSwitch" />
		<Stack Value="HandleCreate" />
		<Stack Value="HandleClose" />
		<Stack Value="HandleDuplicate" />
		<Stack Value="SampledProfile" />
		<Stack Value="ThreadCreate" />
		<Stack Value="ReadyThread" />
	  </Stacks>
	</SystemProvider>
	<EventProvider Id="Microsoft-Windows-Winlogon" Name="dbe9b383-7cf3-4331-91cc-a3cb16a3b538"/>
	<EventProvider Id="Microsoft-Windows-GroupPolicy" Name="aea1b4fa-97d1-45f2-a64c-4d69fffd92c9"/>
	<EventProvider Id="Microsoft-Windows-Wininit" Name="206f6dea-d3c5-4d10-bc72-989f03c8b84b111111"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_Service" Name="89b1e9f0-5aff-44a6-9b44-0a07a7ce5845"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_General" Name="db00dfb6-29f9-4a9c-9b3b-1f4f9e7d9770"/>
	<EventProvider Id="Microsoft-Windows-Folder_Redirection" Name="7d7b0c39-93f6-4100-bd96-4dda859652c5"/>
	<EventProvider Id="Microsoft-Windows-Security-Netlogon" Name="e5ba83f6-07d0-46b1-8bc7-7e669a1d31dca"/>
	<EventProvider Id="Microsoft-Windows-Shell-Core" Name="30336ed4-e327-447c-9de0-51b652c86108"/>
	<Profile Id="SBSL.Verbose.Memory" Name="SBSL" Description="RunningProfile:SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Verbose"> <!-- Default profile. Used when the '-slowlogon' switch is used  -->
	  <ProblemCategories>
		<ProblemCategory Value="First level triage" />
	  </ProblemCategories>
	  <Collectors>
		<SystemCollectorId Value="SBSL_System_Collector">
		  <SystemProviderId Value="SBSL_Collector_Provider" />
		</SystemCollectorId>
		<EventCollectorId Value="SBSL_Event_Collector">
		  <EventProviders>
			<EventProviderId Value="Microsoft-Windows-Winlogon"/>
			<EventProviderId Value="Microsoft-Windows-GroupPolicy"/>
			<EventProviderId Value="Microsoft-Windows-Wininit"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_Service"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_General"/>
			<EventProviderId Value="Microsoft-Windows-Folder_Redirection"/>
			<EventProviderId Value="Microsoft-Windows-Shell-Core"/>
			<EventProviderId Value="Microsoft-Windows-Security-Netlogon"/>
		  </EventProviders>
		</EventCollectorId>
	  </Collectors>
	  <TraceMergeProperties>
		<TraceMergeProperty Id="BaseVerboseTraceMergeProperties" Name="BaseTraceMergeProperties">
		  <DeletePreMergedTraceFiles Value="true" />
		  <FileCompression Value="false" />
		  <InjectOnly Value="false" />
		  <CustomEvents>
			<CustomEvent Value="ImageId" />
			<CustomEvent Value="BuildInfo" />
			<CustomEvent Value="VolumeMapping" />
			<CustomEvent Value="EventMetadata" />
			<CustomEvent Value="PerfTrackMetadata" />
			<CustomEvent Value="WinSAT" />
			<CustomEvent Value="NetworkInterface" />
		  </CustomEvents>
		</TraceMergeProperty>
	  </TraceMergeProperties>
	</Profile>
		<Profile Id="SBSL.Light.Memory" Name="SBSL" Description="RunningProfile:SBSL.Light.Memory" Base="SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Light" /> <!-- Light memory profile. Not currently in use. Reserved for later usage -->
		<Profile Id="SBSL.Verbose.File" Name="SBSL" Description="RunningProfile:SBSL.Verbose.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Verbose" /> <!-- Default -File mode profile. Used when the '-slowlogon' switch is added -->
		<Profile Id="SBSL.Light.File" Name="SBSL" Description="RunningProfile:SBSL.Light.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Light" /> <!-- Light file profile. Not currently in use. Reserved for later usage -->
  </Profiles>
</WindowsPerformanceRecorder>

"@
		Out-file -FilePath "$_LOG_DIR\sbsl.wprp" -InputObject $sbsl_wprp_file -Encoding ascii
	}
}
	
    if ($whfb) {
		if ($ProductType -ne "LanmanNT") {
			$userDnsDomain = $env:USERDNSDOMAIN
			nltest /dsgetdc:$userDnsDomain /force | Out-File -FilePath $_WHFB_LOG_DIR\DsGetDC.txt
		}
		if ($ProductType -eq "LanmanNT") {

			# Dump the affected user
			$GetFormatEnumerationLimit = $FormatEnumerationLimit
			$FormatEnumerationLimit = -1
			$GetErrorActionPreference = $ErrorActionPreference
			$ErrorActionPreference = "SilentlyContinue"
			
			Write-Host 'Enter the username to collect the msDS-keyCredentialLink and admincount attribute' -ForegroundColor Yellow
						
			try{
				$ImpactedUser = Read-Host
				$ImpactedUser2 = Get-ADUser -Identity $ImpactedUser -Properties msDS-keyCredentialLink,admincount
				if ($ImpactedUser2) {
					$ImpactedUser2 | FL SamAccountName, Name, admincount, msDS-keyCredentialLink | Out-File -FilePath $_WHFB_LOG_DIR\ImpactedUser.txt
					write-host "`nData collected for user: $ImpactedUser" -ForegroundColor Green
				}
			}
			catch{
				Write-Host "`nUser $ImpactedUser was not found. Please enter the username again." -ForegroundColor Yellow
			}
			if(!$ImpactedUser2){
				try{
					$ImpactedUser = Read-Host
					$ImpactedUser2 = Get-ADUser -Identity $ImpactedUser -Properties msDS-keyCredentialLink,admincount
					if ($ImpactedUser2) {
						$ImpactedUser2 | FL SamAccountName, Name, admincount, msDS-keyCredentialLink | Out-File -FilePath $_WHFB_LOG_DIR\ImpactedUser.txt
						Write-Host "`nData collected for user: $ImpactedUser" -ForegroundColor Green
					}
				}
				catch{
						Write-Host "`nUser does not exist. Continuing.." -ForegroundColor Yellow
				}
			}
			
			$FormatEnumerationLimit = $GetFormatEnumerationLimit
		
			# AzureADKerberos msDS-NeverRevealGroup membership dump 
			try{
				$groups = Get-Adcomputer -Identity "AzureADKerberos" -Properties msDS-NeverRevealGroup | Select-Object -ExpandProperty msDS-NeverRevealGroup
				if($groups){
					$visitedGroups = @{}
					$allMembers = @{}

					"`nAzureADKerberos: msDS-NeverRevealGroup recursive membership`n" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt
			
					foreach ($groupName in $groups) {
						$groupName = $groupName.Trim()
    
						if ($visitedGroups.ContainsKey($groupName)) {
							continue
						}
    
						$visitedGroups[$groupName] = $true
    
						$members = Get-ADGroupMember -Identity $groupName
						$allMembers[$groupName] = @{Groups=@(); Users=@{}}
    
						foreach ($member in $members) {
							if ($member.objectClass -eq "group") {
								$allMembers[$groupName]["Groups"] += $member.Name
								$nestedMembers = Get-ADGroupMember -Identity $member.Name
								foreach ($nestedMember in $nestedMembers) {
									if ($nestedMember.objectClass -eq "group") {
										$allMembers[$groupName]["Groups"] += $nestedMember.Name
									} else {
										if (-not $allMembers[$groupName]["Users"].ContainsKey($member.Name)) {
											$allMembers[$groupName]["Users"][$member.Name] = @()
										}
										$allMembers[$groupName]["Users"][$member.Name] += $nestedMember.Name
									}
								}
							} else {
								if (-not $allMembers[$groupName]["Users"].ContainsKey($groupName)) {
									$allMembers[$groupName]["Users"][$groupName] = @()
								}
								$allMembers[$groupName]["Users"][$groupName] += $member.Name
							}
						}
					}
					
					$ErrorActionPreference = $GetErrorActionPreference
					
					foreach ($groupName in $allMembers.Keys) {
						if ($allMembers[$groupName]["Groups"].Count -eq 0 -and $allMembers[$groupName]["Users"].Count -eq 0) {
							"Group: $groupName`n" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
						} else {
							"Group: $groupName" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
							"Members:" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
							if ($allMembers[$groupName]["Groups"].Count -gt 0) {
								"- Groups:" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
								foreach ($group in $allMembers[$groupName]["Groups"]) {
									"  - $group" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
									if ($allMembers[$groupName]["Users"].ContainsKey($group)) {
										foreach ($user in $allMembers[$groupName]["Users"][$group]) {
											"    - $user" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
										}
									}
								}
							}
							if ($allMembers[$groupName]["Users"].Count -gt 0) {
								"- Users:" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
								foreach ($grp in $allMembers[$groupName]["Users"].Keys) {
									if (-not $allMembers[$groupName]["Groups"].Contains($grp)) {
										foreach ($user in $allMembers[$groupName]["Users"][$grp]) {
											"  - $user" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
										}
									}
								}
							}
							"" | Out-File -FilePath $_WHFB_LOG_DIR\msDS-NeverRevealGroup.txt -Append
						}
					}
				}
				}
			catch{
			Write-Host "`nAzureADKerberos computer account was not found`n" -ForegroundColor Yellow
			}
		}
	}

	# **slowlogon** ** Generate Slow Logon WPRP file in case the 'slowlogon' switch is added**
	if ($slowlogon) {Generate-slowlogonWPRP}


	# *** QUERY RUNNING PROVIDERS ***
    if ($global:ScriptPrefix -eq 'auth') {
        Add-Content -Path $_PRETRACE_LOG_DIR\running-etl-sessions.txt -value (logman query * -ets)
    }

	#region *** Enable Eventvwr logging ***
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_PRETRACE_LOG_DIR\Capi2_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
	wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_PRETRACE_LOG_DIR\WebAuthn_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CertPoleEng/Operational" 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_PRETRACE_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_PRETRACE_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_PRETRACE_LOG_DIR\WinBio_oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_PRETRACE_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_PRETRACE_LOG_DIR\Aad_oper.evtx /ow:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_PRETRACE_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_PRETRACE_LOG_DIR\Hfb_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_PRETRACE_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
    #endregion *** Enable Eventvwr logging ***	

    # *** ENABLE LOGGING VIA REGISTRY ***

    # NEGOEXT
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

    # PKU2U
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

    # LSA
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC43EFF /f 2>&1 | Out-Null
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 2>&1 | Out-Null
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 2>&1 | Out-Null

    # LSP Logging
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /t REG_DWORD /d 0x41C20800 /f 2>&1 | Out-Null
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /t REG_DWORD /d 0x1 /f 2>&1 | Out-Null

    # Kerberos Logging to SYSTEM event log in case this is a client
    if ($ProductType -eq "WinNT") {
        reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /t REG_DWORD /d 1 /f 2>&1 | Out-Null
    }
    
	
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_PRETRACE_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null


	# **Netlogon logging**
	nltest /dbflag:0x2EBFFFFF 2>&1 | Out-Null

	# **Enabling Group Policy Logging**
	New-Item -Path "$($env:windir)\debug\usermode" -ItemType Directory 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null

	# ** Turn on debug and verbose Cert Enroll  logging **

    if ($global:ScriptPrefix -eq 'auth'){
        write-host "Enabling Certificate Enrollment debug logging...`n"
        write-host "Verbose Certificate Enrollment debug output may be written to this window"
        write-host "It is also written to a log file which will be collected when the stop-auth.ps1 script is run.`n"
    }

	Start-Sleep -s 5

	certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null

	certutil -setreg ngc\Debug 1 2>&1 | Out-Null
	certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null
	
	$InstallationType = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").InstallationType
	if ($InstallationType -notmatch 'Core') {
		Switch -Regex ($osVersionString) {
				'^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...'}
				'^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...'}
				'^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...'}
				'^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...'}
				default {
					Add-Content -Path $_PRETRACE_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
					Add-Content -Path $_PRETRACE_LOG_DIR\DsRegCmdStatus.txt -Value (dsregcmd /status 2>&1) | Out-Null
				}
		}
	}
			
	Add-Content -Path $_PRETRACE_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Services-config.txt -Value (sc.exe query 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null

	Add-Content -Path $_PRETRACE_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null

	# ** Run WPR in case the 'slowlogon' switch is added. (Default File mode = sbsl.wprp!sbsl.verbose -filemode)
	if ($slowlogon){
		wpr -start $_LOG_DIR\sbsl.wprp!sbsl.verbose -filemode
	}

	# *** QUERY RUNNING PROVIDERS ***
	Add-Content -Path $_LOG_DIR\running-etl-sessions.txt -value (logman query * -ets)
	
    ipconfig /flushdns 2>&1 | Out-Null
	

    if ($vAuth.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: vAuth"
	}

	if ($nonet.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: nonet"
	}

	if ($slowlogon.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: slowlogon"
	}
    
    if ($persist.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: persist"
    }
	
	if ($whfb.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: whfb"
	}

	$date = Get-Date
    $utcdate = $date.ToUniversalTime()
    $timezone = (Get-Timezone).DisplayName
    $tz_endindex = $timezone.IndexOf(")")
    Add-Content -Path $_LOG_DIR\script-info.txt -Value "Data collection started on"
    Add-Content -Path $_LOG_DIR\script-info.txt -Value ("    $($date.ToString("yyyy/MM/dd HH:mm:ss")) $($timezone.SubString(1,$tz_endindex-1)) (local time on computer data was collected)")
    Add-Content -Path $_LOG_DIR\script-info.txt -Value ("    $($utcdate.ToString("yyyy/MM/dd HH:mm:ss")) UTC")

    if ($global:ScriptPrefix -eq 'auth'){
        Write-Host "`n
===== Microsoft CSS Authentication Scripts started tracing =====`n
The tracing has now started."
    Write-Host "`nIMPORTANT: The auth scripts make adjustments to the Windows registry to enable certain logging. Please be sure to run stop-auth.ps1 to clean up these adjustments.`n" -ForegroundColor "Yellow"
    }
    
    if ($global:ScriptPrefix -eq 'auth'){
        if ($null -ne $_WatchProcess) {
            if ($_WatchProcess.Name -eq "lsass") { Write-Host "WARNING: When lsass terminates it will cause the machine to restart 60 seconds later.`n" -ForegroundColor "Yellow" }
            Write-Host "Waiting for Process $($_WatchProcess.Name) ($($_WatchProcess.Id)) to terminate"
            Write-Host "Process CTRL+C to cancel"
            Wait-Process -Id $_WatchProcess.Id
            Write-Host "$($_WatchProcess.Name) terminated with Exit Code: $($_WatchProcess.ExitCode)"
            Write-Host "Stopping authscripts"
            Start-Process "powershell" -WorkingDirectory $(Get-Location).Path -ArgumentList  ".\stop-auth.ps1" -NoNewWindow -Wait
        }
        else {
            if ($persist.IsPresent) {
            Write-Host "The auto logger sessions will not start until AFTER the next reboot.`n" -ForegroundColor Yellow
            }
            Write-Host "Once you have created the issue or reproduced the scenario, please run stop-auth.ps1 from this same directory to stop the tracing.
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called `"Authlogs`".
The `"Authlogs`" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"
        }
    }
}

function CollectADS_AuthLog{
	[float]$_Authscriptver = "6"
    if ($global:ScriptPrefix -eq 'TSS'){
	        $_BASE_LOG_DIR = $global:LogFolder #".\authlogs"
            $_LOG_DIR = $_BASE_LOG_DIR
            }
    elseif ($global:ScriptPrefix -eq 'auth') {
        $_BASE_LOG_DIR = $global:_BASE_LOG_DIR
        $_LOG_DIR = $global:_LOG_DIR
        }

	# *** Set some system specifc variables ***
	$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
	$osVersionString = $wmiOSObject.Version
	$osBuildNumString = $wmiOSObject.BuildNumber

	
	# *** Check if script is running ***
    If($global:ScriptPrefix -eq 'auth'){
        If (!(Test-Path $_LOG_DIR\started.txt) -eq "True") {
            Write-Host "
        ===== Microsoft CSS Authentication Scripts started tracing =====`n
        We have detected that tracing has not been started.
        Please run start-auth.ps1 to start the tracing.`n"
            exit
        }
    }

	$_WAM_LOG_DIR = "$_LOG_DIR\WAM"
	$_SCCM_LOG_DIR = "$_LOG_DIR\SCCM-enrollment"
	$_MDM_LOG_DIR = "$_LOG_DIR\DeviceManagement_and_MDM"
	$_CERT_LOG_DIR = "$_LOG_DIR\Certinfo_and_Certenroll"
	$_WHFB_LOG_DIR = "$_LOG_DIR\WHFB"

	New-Item -Path $_WAM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_SCCM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_MDM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_CERT_LOG_DIR -ItemType Directory | Out-Null
	

	Add-Content -Path $_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
	Add-Content -Path $_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
	Add-Content -Path $_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null
    
	# *** Stop WPR - Checking if the slowlogon switched was passed ***
	$CheckIfslowlogonWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "slowlogon"
	if ($CheckIfslowlogonWasPassed.Pattern -eq "slowlogon") {
		Write-Host "Stopping WPR. This may take some time depending on the size of the WPR Capture, please wait...."

		# Stop WPR
		wpr -stop $_LOG_DIR\SBSL.etl
	}

	# *** CLEAN UP ADDITIONAL LOGGING ***
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null

	if ($ProductType -eq "WinNT") {
		reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1 | Out-Null
	}

	reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f  2>&1 | Out-Null
	nltest /dbflag:0x0  2>&1 | Out-Null

	# *** Event/Operational logs
    
    If($global:ScriptPrefix -eq 'auth'){
        write-host "The Security event viewer log is not collected by default. Collect it manually if needed.`n" -ForegroundColor Yellow
    }
	
    wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_LOG_DIR\Capi2_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" $_LOG_DIR\Kerb_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" $_LOG_DIR\Kdc_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" $_LOG_DIR\KdcProxy_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe export-log "Microsoft-Windows-NTLM/Operational" $_LOG_DIR\\NTLM_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-WebAuth/Operational" $_LOG_DIR\WebAuth_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_LOG_DIR\WebAuthn_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-CertPoleEng/Operational" $_LOG_DIR\Certpoleng_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > $_CERT_LOG_DIR\CertificateServicesClientLog.xml 2>&1 | Out-Null
    certutil -policycache $_LOG_DIR\CertificateServicesClientLog.xml > $_LOG_DIR\ReadableClientLog.txt 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational"  /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" $_LOG_DIR\Auth_Policy_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUser-Client" $_LOG_DIR\Auth_ProtectedUser_Client.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" $_LOG_DIR\Auth_ProtectedUser_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null
	    
	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" $_LOG_DIR\Auth_ProtectedUser_Success_DC.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_LOG_DIR\WinBio_oper.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" $_LOG_DIR\Aad_Analytic.evtx /overwrite:true 2>&1 | Out-Null
		
    wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_LOG_DIR\Aad_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe export-log "Microsoft-Windows-AADRT/Admin" $_LOG_DIR\Aadrt_admin.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" $_LOG_DIR\UsrDeviceReg_Dbg.evtx /overwrite:true 2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false  2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_LOG_DIR\Hfb_Oper.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

    wevtutil.exe export-log SYSTEM $_LOG_DIR\System.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe export-log APPLICATION $_LOG_DIR\Application.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Shell-Core/Operational" $_LOG_DIR\ShellCore_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-WMI-Activity/Operational" $_LOG_DIR\WMI-Activity_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe export-log "Microsoft-Windows-GroupPolicy/Operational" $_LOG_DIR\GroupPolicy.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-System_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-User_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

    wevtutil.exe export-log "Microsoft-Windows-Kernel-Boot/Operational" $_LOG_DIR\Kernel_Boot.evtx /overwrite:true  2>&1 | Out-Null
	
    wevtutil.exe export-log "Microsoft-Windows-User Profile Service/Operational" $_LOG_DIR\UserProfileService_Oper.evtx /overwrite:true  2>&1 | Out-Null
	
    # PNP state export
    pnputil.exe /export-pnpstate $_LOG_DIR\pnpstate.pnp  | Out-Null
	
    # TPM diagnostics and measurement logs
    New-Item -Path $_LOG_DIR -Name "TPMDiagnostics" -ItemType "directory" | Out-Null
    $_TPM_LOG_DIR = "$_LOG_DIR\TPMDiagnostics"
    if (test-path "$env:WINDIR\System32\TpmTool.exe")
    {
        TpmTool.exe gatherlogs $_TPM_LOG_DIR | Out-Null
    }
    if (test-path "$env:WINDIR\Logs\MeasuredBoot")
    {
        Copy-Item -Path "$env:WINDIR\Logs\MeasuredBoot\*" -Destination $_TPM_LOG_DIR
    }

    # ***COLLECT NGC DETAILS***
	$InstallationType = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").InstallationType
	if ($InstallationType -notmatch 'Core') {
		Switch -Regex ($osVersionString) {
			'^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...'}
			'^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...'}
			'^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...'}
			'^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...'}
			default {
				Add-Content -Path $_LOG_DIR\Dsregcmd.txt -Value (dsregcmd /status 2>&1) | Out-Null
				Add-Content -Path $_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
			}
		}
	}
	certutil -delreg Enroll\Debug  2>&1 | Out-Null
	certutil -delreg ngc\Debug  2>&1 | Out-Null
	certutil -delreg Enroll\LogLevel  2>&1 | Out-Null

	Copy-Item -Path "$($env:windir)\Ngc*.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Get-ChildItem -Path $_LOG_DIR -Filter "Ngc*.log" | Rename-Item -NewName { "Pregenlog_" + $_.Name } 2>&1 | Out-Null

	Copy-Item -Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\settings\settings.dat" -Destination $_WAM_LOG_DIR\settings.dat -Force 2>&1 | Out-Null

	if ((Test-Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\") -eq "True") {
		$WAMAccountsFullPath = GCI "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\*.tbacct"
		foreach ($WAMAccountsFile in $WAMAccountsFullPath) {
			"File Name: " + $WAMAccountsFile.name + "`n" >> $_WAM_LOG_DIR\tbacct.txt
			Get-content -Path $WAMAccountsFile.FullName >> $_WAM_LOG_DIR\tbacct.txt -Encoding Unicode | Out-Null
			"`n`n" >> $_WAM_LOG_DIR\tbacct.txt
		}
	}

	# *** Checking if Network trace is running ***
    if ($global:ScriptPrefix -eq 'auth') {
        $CheckIfNonetWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "nonet"
        if ($CheckIfNonetWasPassed.Pattern -ne "nonet") {
            Write-Host "`n
            Stopping Network Trace and merging
            This may take some time depending on the size of the network capture, please wait....`n"

            # Stop Network Trace
            netsh trace stop 2>&1 | Out-Null
        }
    }

	Add-Content -Path $_LOG_DIR\Ipconfig-info.txt -Value (ipconfig /all 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null

	# ***Netlogon, LSASS, LSP, Netsetup and Gpsvc log***
	Copy-Item -Path "$($env:windir)\debug\Netlogon.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\system32\Lsass.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\Lsp.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\Netsetup.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\usermode\gpsvc.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null

	# ***Credman***
	Add-Content -Path $_LOG_DIR\Credman.txt -Value (cmdkey.exe /list 2>&1) | Out-Null

	# ***Build info***
	$ProductName = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName
	$DisplayVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").DisplayVersion
	$InstallationType = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").InstallationType
	$CurrentVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
	$ReleaseId = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId
	$BuildLabEx = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx
	$CurrentBuildHex = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild
	$UBRHEX = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").UBR

	Add-Content -Path $_LOG_DIR\Build.txt -Value ($env:COMPUTERNAME + " " + $ProductName + " " + $InstallationType + " Version:" + $CurrentVersion + " " + $DisplayVersion + " Build:" + $CurrentBuildHex + "." + $UBRHEX) | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("-------------------------------------------------------------------") | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("BuildLabEx: " + $BuildLabEx) | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("---------------------------------------------------") | Out-Null

    $SystemFiles = @(
        "$($env:windir)\System32\kerberos.dll"
        "$($env:windir)\System32\lsasrv.dll"
        "$($env:windir)\System32\netlogon.dll"
        "$($env:windir)\System32\kdcsvc.dll"
        "$($env:windir)\System32\msv1_0.dll"
        "$($env:windir)\System32\schannel.dll"
        "$($env:windir)\System32\dpapisrv.dll"
        "$($env:windir)\System32\basecsp.dll"
        "$($env:windir)\System32\scksp.dll"
        "$($env:windir)\System32\bcrypt.dll"
        "$($env:windir)\System32\bcryptprimitives.dll"
        "$($env:windir)\System32\ncrypt.dll"
        "$($env:windir)\System32\ncryptprov.dll"
        "$($env:windir)\System32\cryptsp.dll"
        "$($env:windir)\System32\rsaenh.dll"
        "$($env:windir)\System32\Cryptdll.dll"
        "$($env:windir)\System32\cloudAP.dll"
    )

    ForEach ($File in $SystemFiles) {
        if (Test-Path $File -PathType leaf) {
            $FileVersionInfo = (get-Item $File).VersionInfo
            $FileBuildInfo = $FileVersionInfo.FileVersionRaw
            Add-Content -Path $_LOG_DIR\Build.txt -Value ($FileVersionInfo.FileName + ",  " + $FileBuildInfo.ToString()) | Out-Null
        }
    }

	#region ***Reg Exports***
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /s > $_LOG_DIR\Lsa-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > $_LOG_DIR\Policies-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft" /s > $_LOG_DIR\GlobalGP-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > $_LOG_DIR\SystemGP-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /s > $_LOG_DIR\Lanmanserver-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /s > $_LOG_DIR\Lanmanworkstation-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" /s > $_LOG_DIR\Netlogon-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /s > $_LOG_DIR\Schannel-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMControl-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-Policies-key.txt 2>&1 | Out-Null

    reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-Policies-key.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" /s > $_LOG_DIR\SCardCredentialProviderGP-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key-Wow64.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > $_LOG_DIR\Winlogon-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > $_LOG_DIR\Winlogon-Policies-key.txt 2>&1 | Out-Null
    
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon" /s > $_LOG_DIR\Winlogon-CCS-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore" /s > $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
    reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" /s > $_LOG_DIR\KDC-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc" /s >> $_LOG_DIR\KDC-key.txt 2>&1 | Out-Null
	
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC" /s > $_LOG_DIR\KDCProxy-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" /s > $_LOG_DIR\Kerb_policies.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > $_LOG_DIR\RegCDJ-key.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-key.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC" /s > $_LOG_DIR\RegAADNGC-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-Policy-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > $_LOG_DIR\Winbio-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > $_LOG_DIR\Wbiosrvc-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /s > $_LOG_DIR\Winbio-Policy-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > $_LOG_DIR\Eas-key.txt 2>&1 | Out-Null

    reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP" /s > $_LOG_DIR\Scep-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient" /s > $_LOG_DIR\MachineId.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork" /s > $_LOG_DIR\NgcPolicyIntune-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGp-key.txt 2>&1  | Out-Null
    reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGpUser-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc" /s > $_LOG_DIR\NgcCryptoConfig-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > $_LOG_DIR\DeviceLockPolicy-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey " /s > $_LOG_DIR\FIDOPolicyIntune-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO" /s > $_LOG_DIR\FIDOGp-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /s > $_LOG_DIR\RpcGP-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /s > $_LOG_DIR\NTDS-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /s > $_LOG_DIR\LdapClient-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s > $_LOG_DIR\DeviceGuard-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup" /s > $_SCCM_LOG_DIR\CCMSetup-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM" /s > $_SCCM_LOG_DIR\CCM-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" > $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC" > $_LOG_DIR\SharedPC.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess" > $_LOG_DIR\Passwordless.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz" /s > $_LOG_DIR\Authz-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" > $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" >> $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" > $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
    reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CDJ\AAD" /s > $_LOG_DIR\CDJ-AAD.txt 2>&1 | Out-Null

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TokenBroker" /s >> $_LOG_DIR\TokenBroker-key.txt 2>&1 | Out-Null
    reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\TokenBroker" /s >> $_LOG_DIR\TokenBroker-key.txt 2>&1 | Out-Null
    #endregion ***Reg Exports***

    	Add-Content -Path $_LOG_DIR\http-show-sslcert.txt -Value (netsh http show sslcert 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\http-show-urlacl.txt -Value (netsh http show urlacl 2>&1) | Out-Null

	Add-Content -Path $_LOG_DIR\trustinfo.txt -Value (nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V 2>&1) | Out-Null

	$domain = (Get-WmiObject Win32_ComputerSystem).Domain
	switch ($ProductType) {
		"WinNT" {
			Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
		}
		"ServerNT" {
			Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
		}
	}

	# ***Cert info***
	Add-Content -Path $_CERT_LOG_DIR\Machine-Store.txt -Value (certutil -v -silent -store my 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\User-Store.txt -Value (certutil -v -silent -user -store my 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Scinfo.txt -Value (Certutil -v -silent -scinfo 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Tpm-Cert-Info.txt -Value (certutil -tpminfo 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\CertMY_SmartCard.txt -Value (certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert_MPassportKey.txt -Value (Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Homegroup-Machine-Store.txt -Value (certutil -v -silent -store "Homegroup Machine Certificates" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\NTAuth-store.txt -Value (certutil -v -enterprise -store NTAuth 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-AD-store.txt -Value (certutil -v -store -enterprise root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-Registry-store.txt -Value (certutil -v -store root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-ThirdParty-Store.txt -Value (certutil -v -store authroot 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-AD-store.txt -Value (certutil -v -store -enterprise ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-Registry-store.txt -Value (certutil -v -store ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-machine.txt -Value (certutil -v -template 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-user.txt -Value (certutil -v -template -user 2>&1) | Out-Null

	$CheckIfwhfbWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "whfb"
	if (($CheckIfwhfbWasPassed.Pattern -eq "whfb") -and ($ProductType -eq "LanmanNT")) {
		Add-Content -Path $_WHFB_LOG_DIR\KDC-Store.txt -Value (Certutil -v -store -service -service KDC\MY 2>&1) | Out-Null
		Add-Content -Path $_WHFB_LOG_DIR\NTDS-Store.txt -Value (Certutil -v -store -service -service NTDS\MY 2>&1) | Out-Null
	}

	# *** Cert enrolment info
	Copy-Item "$($env:windir)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromWindir.log -Force 2>&1 | Out-Null

	Copy-Item "$($env:windir)\certmmc.log" -Destination $_CERT_LOG_DIR\CAConsole.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certocm.log" -Destination $_CERT_LOG_DIR\ADCS-InstallConfig.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certsrv.log" -Destination $_CERT_LOG_DIR\ADCS-Debug.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\CertUtil.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certutil.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certreq.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certreq.log -Force 2>&1 | Out-Null

	Copy-Item "$($env:userprofile)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromUserProfile.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:LocalAppData)\CertEnroll.log" -Destination $_CERT_LOG_DIRCertEnroll\CertEnroll-fromLocalAppData.log -Force 2>&1 | Out-Null

	Add-Content -Path $_LOG_DIR\Schtasks.query.v.txt -Value (schtasks.exe /query /v 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Schtasks.query.xml.txt -Value (schtasks.exe /query /xml 2>&1) | Out-Null

    If($global:ScriptPrefix -eq 'auth'){
        Write-Host "Collecting Device enrollment information, please wait....`n"
    }

	# **SCCM**
	$_SCCM_DIR = "$($env:windir)\CCM\Logs"
	If (Test-Path $_SCCM_DIR) {
		Copy-Item $_SCCM_DIR\CertEnrollAgent*.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\StateMessage*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\DCMAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\ClientLocation*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmEval*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmRepair*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\PolicyAgent.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CIDownloader.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\PolicyEvaluator.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\DcmWmiProvider*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CIAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmMessaging.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\ClientIDManagerStartup.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\LocationServices.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
	}

	$_SCCM_DIR_Setup = "$($env:windir)\CCMSetup\Logs"
	If (Test-Path $_SCCM_DIR_Setup) {
		Copy-Item $_SCCM_DIR_Setup\ccmsetup.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
	}

	# ***MDM***
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments" /s > $_MDM_LOG_DIR\MDMEnrollments-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager" /s > $_MDM_LOG_DIR\MDMEnterpriseResourceManager-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-User-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-SystemUser-key.txt 2>&1 | Out-Null

	wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text > $_MDM_LOG_DIR\DmEventLog.txt 2>&1 | Out-Null

	#DmEventLog.txt and Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.txt might contain the same content
	$DiagProvierEntries = wevtutil el
	foreach ($DiagProvierEntry in $DiagProvierEntries) {
		$tempProvider = $DiagProvierEntry.Split('/')
		if ($tempProvider[0] -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider") {
			wevtutil qe $($DiagProvierEntry) /f:text /l:en-us > "$_MDM_LOG_DIR\$($tempProvider[0])-$($tempProvider[1]).txt"   2>&1 | Out-Null
		}
	}
	

    # ***MDM***
    $mdmDiagTool = "$($env:windir)\system32\mdmdiagnosticstool.exe"
    $mdmfallback = $false

    # mdmdiagnosticstool.exe doesn't like relative paths
    $MDMDiagOutput = (Resolve-Path $_MDM_LOG_DIR).Path

    # Use mdmdiagnosticstool.exe if available
    # Tool does not seem to work on RS1 and earlier
    if([version]$osVersionString -gt [version]"10.0.14393" -and (Test-Path $mdmDiagTool)) {
        & "$mdmDiagTool" -area "OsConfiguration;DeviceEnrollment;DeviceProvisioning" -zip "$MDMDiagOutput\mdmdiag.zip" 2>&1 | Out-Null
    
        # Fall back if the diag report wasn't generated
        if(!(Test-Path "$_MDM_LOG_DIR\mdmdiag.zip")) {
            $mdmfallback = $true
        }
    }
    else {
        $mdmfallback = $true
    }

    # Fallback to manual copy of MDM logs
    if($mdmfallback) {
        reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments" /s > $_MDM_LOG_DIR\MDMEnrollments-key.txt 2>&1 | Out-Null
        reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager" /s > $_MDM_LOG_DIR\MDMEnterpriseResourceManager-key.txt 2>&1 | Out-Null
        reg query "HKEY_CURRENT_USER\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-User-key.txt 2>&1 | Out-Null
        reg query "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-SystemUser-key.txt 2>&1 | Out-Null
    
        wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text > $_MDM_LOG_DIR\DmEventLog.txt 2>&1 | Out-Null
    
        #DmEventLog.txt and Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.txt might contain the same content
        $DiagProvierEntries = wevtutil el
        foreach ($DiagProvierEntry in $DiagProvierEntries) {
            $tempProvider = $DiagProvierEntry.Split('/')
            if ($tempProvider[0] -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider") {
                wevtutil qe $($DiagProvierEntry) /f:text /l:en-us > "$_MDM_LOG_DIR\$($tempProvider[0])-$($tempProvider[1]).txt"   2>&1 | Out-Null
            }
        }
    }

    If($global:ScriptPrefix -eq 'auth'){
	    Write-Host "Collecting Device configuration information, please wait....`n"
    }

	Add-Content -Path $_LOG_DIR\Services-config.txt -Value (sc.exe query 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\FilterManager.txt -Value (fltmc 2>&1) | Out-Null
	Gpresult /h $_LOG_DIR\GPOresult.html 2>&1 | Out-Null

    # Check if we are running on a DC
    if ($ProductType -eq "LanmanNT") {
        Add-Content -Path $_LOG_DIR\FSMO.txt -Value (netdom query fsmo /server . 2>&1) | Out-Null
        Add-Content -Path $_LOG_DIR\DC_List.txt -Value (nltest /dclist:$domain /server:. 2>&1) | Out-Null   
    }

	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath $_LOG_DIR\Env.txt | Out-Null

	# ***Hotfixes***
    Get-WmiObject -Class "win32_quickfixengineering" | Select -Property Description, HotfixID, @{Name = "InstalledOn"; Expression = { ([DateTime]($_.InstalledOn)).ToLocalTime() } }, Caption | Out-File -Append $_LOG_DIR\Qfes_installed.txt

    Add-Content -Path $_LOG_DIR\whoami.txt -Value (Whoami /all 2>&1) | Out-Null

    $date = Get-Date
    $utcdate = $date.ToUniversalTime()
    $timezone = (Get-Timezone).DisplayName
    $tz_endindex = $timezone.IndexOf(")")
    Add-Content -Path $_LOG_DIR\script-info.txt -Value "Data collection stopped on"
    Add-Content -Path $_LOG_DIR\script-info.txt -Value ("    $($date.ToString("yyyy/MM/dd HH:mm:ss")) $($timezone.SubString(1,$tz_endindex-1)) (local time on computer data was collected)")
    Add-Content -Path $_LOG_DIR\script-info.txt -Value ("    $($utcdate.ToString("yyyy/MM/dd HH:mm:ss")) UTC")

    Remove-Item -Path $_LOG_DIR\started.txt -Force | Out-Null
    
    If($global:ScriptPrefix -eq 'auth'){
    Write-Host "`n
===== Microsoft CSS Authentication Scripts tracing stopped =====`n
The tracing has now stopped and data has been saved to the ""Authlogs"" sub-directory.
The ""Authlogs"" directory contents (including subdirectories) can be supplied to Microsoft CSS engineers for analysis.`n`n
======================= IMPORTANT NOTICE =======================`n
The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, Device names, and User names.`n
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called ""Authlogs"".
The ""Authlogs"" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"
    }

}

#endregion ### Pre-Start (ADS_AuthPreStart called by start-auth.ps1) / Post-Stop (CollectADS_AuthLog called by stop-auth.ps1) / Collect functions for trace components and scenarios

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIIoKgYJKoZIhvcNAQcCoIIoGzCCKBcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB4RNyub1I0uqAm
# ZN5yfFdWbRk+NWPKswX9JOWWEUzOJqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDrq5aJOCa1Vgnvw2vCuBedj
# HLT+wLQt66iVUyvCAHulMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAf1s6V0GVq9Or40To6EKgzepWsmy3LG5fb3SbMhjNebJkAlMDi73oCiKM
# Zuc0DLkq674fhX3bW3YADHRrlWpANk8vwqYdsM3YZY9z2Srm1msCUtNzFOxVCfO6
# YqSkBimmtv1rqdOhUpSqaHZQriEwrex57aqvjksKfCUkSCSjjCTv7YZ1Shq1ptWp
# BnVLnXtELhab1CuYMJy8Qx5Bc75v2rLjictQqCcQNunTZKWP0afcutbewUmCiooQ
# v2Bi/mgqLKAt4Zkc7R0VrwSuVPvY3eyOdXIDVmLJULzkv9ilZEEk+XquMdArgg3s
# CFPThAB73XLG7FO7FjVvN2LNDgctzKGCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCC
# F3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAztaBf7g7BxK9fDDBhL9QwvMB/j/gZivd4CR7gpPjNJAIGaNfLQ4cI
# GBMyMDI1MTAwOTEyMTQzNC45ODFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# CSqGSIb3DQEJBDEiBCBHFB0AykTXH4GCBilS43gKWjG0mLnzz/UjkpRg3OyQhzCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIN1Hd5UmKnm7FW7xP3niGsfHJt4x
# R8Xu+MxgXXc0iqn4MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAIPV5pHFEDmRuYAAQAAAg8wIgQg+9TdlXyqJ9IiwRp5fl6vcyHiaSwg
# dHpZdXnsu2KobakwDQYJKoZIhvcNAQELBQAEggIAkfLZVRd4OzlzFEBtt3prip72
# 69bhFBgJGnPB5FGCbNPc9Qc58hvjkUwVB5/dEY+5SQbmr5eRsdOBBP3nVQAYs0tx
# eEgDx/lQGvExgVxvOB5QNn8FANxKTw2+cThBIwflY//F7vrz5qIWzM2UUeycl74e
# KtJ9UtC1owdPNgcIXuqXi2T++GpbMs/Hior59S08xtCpSxHlJGhZKvvZ3P2TLpJ+
# dgOOoVZ/rtDXvPBocOdKhhZEDaRQr/HgXTH/2NuR5QOyz5k8wASEgOOSNECckuDD
# B/lX793FAFfu9TSNsH6QFD2ksFhvDCRIxGNIWYMvrAEkHHNVGmdm0Re31vn0OTKn
# ztV9W5eKPhSvycB471nIDz/FDotSkvFiF1LwClcmC5zjgbSqkUkGNYgMxjfoBARV
# zJXel17nmlzI0zNGdhu5wrVsIjP63aDKTIW2ZbU/e4kkhDzkbOjtuaKYjOnTLrAy
# Y2xslRYjVVCqKV30EhPOOfXs5FcNR1bI88PlDC1tR1QPSqZtRdHXYYbv5N+1VQRZ
# 71dyjLDmeJwUSNBz33HDbBmQ1XbUnufWjpKuGynYxa/TquydnIDsvs2Lh0tTdq1X
# qdPszF5QL0keirlt3ViPpgq0x7Pf/rweRxGJpYLE205fm2ISn1E/P5wX2keQc57w
# eyhwwfyDg2DXh3x6Lu8=
# SIG # End signature block
