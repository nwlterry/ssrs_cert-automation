<#
.SYNOPSIS 
    Universal SSRS Certificate Auto-Renewal & Auto-Rebind Handler (CN + SAN Version)
    Supports: SQL Server 2016 - 2025 SSRS & Power BI Report Server (PBIRS)
#>
Param( 
    [String]$OldCertHash, 
    [Parameter(Mandatory=$true)][String]$NewCertHash, 
    [Int32]$EventRecordId,
    [switch]$DebugMode = $false
)

# =====================================================================
# CONFIGURATION
# =====================================================================
$ExpectedTemplateName = "Web Server ( Auto Renew )"
$LogPath = "$env:ProgramData\CertificateNotificationTasks"
$LogFilePath = Join-Path $LogPath "SSRSCertRebind.log"
$EventSource = "SSRS-Cert-Rebind"
# =====================================================================

# Ensure Directory Exists
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null } 

# Ensure Event Source Exists
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction SilentlyContinue } catch {}
}

# Custom Logging Function
function Write-Log {
    Param(
        [Parameter(Mandatory=$true)][String]$Message,
        [ValidateSet('Info', 'Warning', 'Error')][String]$Level = 'Info',
        [switch]$IsDebugMessage
    )
    if ($IsDebugMessage -and -not $DebugMode) { return }

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "[$Timestamp] [$Level] $Message"
    
    # 1. Console Output (for manual testing)
    if ($Level -eq 'Error') { Write-Host $LogLine -ForegroundColor Red }
    elseif ($Level -eq 'Warning') { Write-Host $LogLine -ForegroundColor Yellow }
    else { Write-Host $LogLine -ForegroundColor Cyan }

    # 2. File Log
    $LogLine | Out-File -FilePath $LogFilePath -Append -Encoding UTF8

    # 3. Event Log (Skip debug messages in Event Viewer to reduce noise)
    if (-not $IsDebugMessage) {
        $EntryType = switch ($Level) { 'Info' { 'Information' }; 'Warning' { 'Warning' }; 'Error' { 'Error' } }
        $EventID = switch ($Level) { 'Info' { 1000 }; 'Warning' { 1001 }; 'Error' { 1002 } }
        try { Write-EventLog -LogName 'Application' -Source $EventSource -EntryType $EntryType -EventId $EventID -Message $Message -ErrorAction SilentlyContinue } catch {}
    }
}

Write-Log "Starting SSRS Certificate Rebind Process (CN+SAN). EventRecordId: $EventRecordId"

# 1. Duplicate Execution Prevention
$StateFile = Join-Path $LogPath "LastProcessedEventRecordId.txt"
if ($EventRecordId) { 
    $LastId = if (Test-Path $StateFile) { Get-Content $StateFile -EA SilentlyContinue } else { 0 } 
    if ($EventRecordId -le $LastId) {  
        Write-Log "Event $EventRecordId already processed. Exiting." -IsDebugMessage
        return  
    }
}

$OldCertHash = $OldCertHash?.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { 
    Write-Log "New certificate $NewCertHash not found in LocalMachine\My store." -Level Error
    return
}

Write-Log "New Cert Subject: $($NewCertificate.Subject)" -IsDebugMessage

# 2. Extract DNS Names (CN + SAN DNS only)
$DnsNames = @()
$SanExt = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
if ($SanExt) { 
    $DnsNames += ($SanExt.Format(1) -split "`n" | Where-Object { $_ -match '^DNS Name=' } | ForEach-Object { ($_ -replace '^DNS Name=', '').Trim() })
}
if ($NewCertificate.Subject -match 'CN=([^,]+)') { 
    $CN = $Matches[1].Trim()
    if ($DnsNames -notcontains $CN) { $DnsNames += $CN }
}

if (-not $DnsNames) { Write-Log "Could not extract DNS Names or CN." -Level Error; return }
Write-Log "Names for Binding: $($DnsNames -join ', ')" -IsDebugMessage

# 3. Verify Certificate Template Match
if ($ExpectedTemplateName) {
    Write-Log "Verifying Template. Expecting: '$ExpectedTemplateName'" -IsDebugMessage
    $certTemplateExtension = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }
    
    if (-not $certTemplateExtension) { Write-Log "No Template Info found. Skipping." -Level Warning; return }

    $CertTemplateOid = [regex]::Match($certTemplateExtension.Format(0), '1\.3\.6\.1\.4\.1\.311\.21\.8\.[0-9\.]+').Value
    if ($CertTemplateOid) {
        $TemplateMatched = $false
        try {
            $RootDSE = [ADSI]"LDAP://RootDSE"
            $Searcher = [adsisearcher]"(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$CertTemplateOid))"
            $Searcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($RootDSE.configurationNamingContext)"
            $Result = $Searcher.FindOne()
            if ($Result) {
                if (($Result.Properties["name"][0] -eq $ExpectedTemplateName) -or ($Result.Properties["displayname"][0] -eq $ExpectedTemplateName)) { $TemplateMatched = $true }
            }
        } catch {}

        if (-not $TemplateMatched -and ($certTemplateExtension.Format(0) -match [regex]::Escape($ExpectedTemplateName))) { $TemplateMatched = $true }

        if (-not $TemplateMatched) { Write-Log "Template doesn't match '$ExpectedTemplateName'. Skipping." -Level Warning; return }
    } else {
        Write-Log "Could not parse Template OID string. Skipping." -Level Error; return
    }
}

# 4. Dynamically Discover WMI Namespaces
$SsrsConfigs = @()
$RootNs = "root\Microsoft\SqlServer\ReportServer"
if (Get-CimClass -Namespace $RootNs -ErrorAction SilentlyContinue) {
    foreach ($Instance in (Get-CimInstance -Namespace $RootNs -ClassName __NAMESPACE -EA SilentlyContinue).Name) {
        foreach ($Version in (Get-CimInstance -Namespace "$RootNs\$Instance" -ClassName __NAMESPACE -EA SilentlyContinue).Name) {
            try { $SsrsConfigs += Get-CimInstance -Namespace "$RootNs\$Instance\$Version\Admin" -ClassName MSReportServer_ConfigurationSetting -EA Stop } catch {}
        }
    }
}

if (-not $SsrsConfigs) { Write-Log "No SSRS/PBIRS instances found." -Level Error; return }

# 5. Process Instances
$Port = 443; $SystemLocale = Get-Culture 
foreach ($Config in $SsrsConfigs) {
    Write-Log "Processing Instance: $($Config.InstanceName)"
    $Success = $false

    foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) { 
        foreach ($Name in $DnsNames) { 
            $Url = "https://$Name`:$Port" 
            try { 
                $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{ Application = $App; UrlString = $Url; Lcid = $SystemLocale.LCID } -EA Stop 
                if ($Result.HRESULT -eq 0 -or $Result.HRESULT -eq -2147220932) { $Success = $true }
            } catch { Write-Log "ReserveURL failed for $Url : $($_.Exception.Message)" -Level Warning } 
        }

        if ($OldCertHash) {
            try { $Config | Invoke-CimMethod -MethodName RemoveSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $OldCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -EA Stop | Out-Null
            } catch { Write-Log "RemoveSSLCertificateBinding ($App): No old binding found/removal failed." -IsDebugMessage }
        }

        try { 
            $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $NewCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -EA Stop 
            if ($Result.HRESULT -eq 0) { $Success = $true; Write-Log "Successfully bound new cert to $App" } 
        } catch { Write-Log "CreateSSLCertificateBinding failed: $($_.Exception.Message)" -Level Error } 
    }

    if (-not $Config.IsInitialized) { try { $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{ InstallationID = $Config.InstallationID } | Out-Null } catch {} } 

    if ($Success) { 
        $TargetService = if ($Config.ServiceName) { $Config.ServiceName } else { 'SQLServerReportingServices' }
        try {
            Restart-Service -Name $TargetService -Force -EA Stop
            Write-Log "Successfully restarted service: $TargetService" 
        } catch { Write-Log "Failed to restart service '$TargetService'. Error: $($_.Exception.Message)" -Level Warning }
    }
}

if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
Write-Log "Processing completed successfully."
