<#
.SYNOPSIS 
    Universal SSRS Certificate Auto-Renewal & Auto-Rebind Handler 
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
# Define the required Certificate Template Name here. 
# The script will only process certificates issued by this template.
$ExpectedTemplateName = "Web Server ( Auto Renew )"
# =====================================================================

if ($DebugMode) { Write-Output "=== DEBUG MODE ENABLED ===" }

# 1. Duplicate Execution Prevention
$StatePath = "$env:ProgramData\CertificateNotificationTasks"
$StateFile = Join-Path $StatePath "LastProcessedEventRecordId.txt"

if ($EventRecordId) { 
    if (-not (Test-Path $StatePath)) { New-Item -ItemType Directory -Path $StatePath -Force | Out-Null } 
    $LastId = if (Test-Path $StateFile) { Get-Content $StateFile -EA SilentlyContinue } else { 0 } 
    if ($EventRecordId -le $LastId) {  
        Write-Output "Event $EventRecordId already processed. Exiting." 
        return  
    }
}

$OldCertHash = $OldCertHash.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { throw "New certificate $NewCertHash not found in LocalMachine\My store." }

if ($DebugMode) { Write-Output "New Cert Subject : $($NewCertificate.Subject)"}

# 2. Extract DNS Names (Subject Alternative Names & Subject)
$DnsNames = @()
$SanExt = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
if ($SanExt) { 
    $DnsNames += ($SanExt.Format(1) -split "`n" | Where-Object { $_ -match '^DNS Name=' } | ForEach-Object { ($_ -replace '^DNS Name=', '').Trim() })
}
if (-not $DnsNames -and $NewCertificate.Subject -match 'CN=([^,]+)') { 
    $DnsNames += $Matches[1].Trim()
}
if ($DebugMode) { Write-Output "DNS Names: $($DnsNames -join ', ')" }

# 3. Verify Certificate Template Match
if ($ExpectedTemplateName) {
    Write-Output "Template verification active. Expecting: '$ExpectedTemplateName'"
    
    # 1.3.6.1.4.1.311.21.7 is the V2 Certificate Template Information extension
    $certTemplateExtension = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }
    
    if (-not $certTemplateExtension) {
        Write-Output "No Template Information OID found on certificate. Skipping."
        if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
        return
    }

    # Extract the exact Enterprise Template OID via Regex
    $CertTemplateOid = [regex]::Match($certTemplateExtension.Format(0), '1\.3\.6\.1\.4\.1\.311\.21\.8\.[0-9\.]+').Value
    
    if ($CertTemplateOid) {
        if ($DebugMode) { Write-Output "Extracted Template OID from Cert: $CertTemplateOid" }
        $TemplateMatched = $false

        # Method A: Reliable ADSI Lookup directly against the Configuration Partition
        try {
            $RootDSE = [ADSI]"LDAP://RootDSE"
            $ConfigContext = $RootDSE.configurationNamingContext
            $Searcher = [adsisearcher]"(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$CertTemplateOid))"
            $Searcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
            $Result = $Searcher.FindOne()

            if ($Result) {
                $ADName = $Result.Properties["name"][0]
                $ADDisplayName = $Result.Properties["displayname"][0]
                if ($DebugMode) { Write-Output "Resolved OID in AD to Template: $ADName / $ADDisplayName" }

                if (($ADName -eq $ExpectedTemplateName) -or ($ADDisplayName -eq $ExpectedTemplateName)) {
                    $TemplateMatched = $true
                }
            }
        } catch {
            if ($DebugMode) { Write-Warning "ADSI Lookup failed, falling back to local string match." }
        }

        # Method B: Fallback to local extension text if AD is unreachable
        if (-not $TemplateMatched) {
            if ($certTemplateExtension.Format(0) -match [regex]::Escape($ExpectedTemplateName)) {
                if ($DebugMode) { Write-Output "Matched template name via local extension fallback." }
                $TemplateMatched = $true
            }
        }

        if (-not $TemplateMatched) {
            Write-Output "Certificate template does not match expected name: '$ExpectedTemplateName'. Skipping."
            if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
            return
        } else {
            Write-Output "✓ Certificate verified. Matches template: $ExpectedTemplateName"
        }
    } else {
        Write-Output "Could not parse Template OID string from certificate extension. Skipping."
        if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
        return
    }
}

# 4. Dynamically Discover SSRS / PBIRS WMI Namespaces (2016 - 2025)
$SsrsConfigs = @()
$RootNs = "root\Microsoft\SqlServer\ReportServer"

if (Get-CimClass -Namespace $RootNs -ErrorAction SilentlyContinue) {
    # Find all instances (e.g., RS_SSRS, RS_MSSQLSERVER, PBIRS)
    $SsrsInstances = Get-CimInstance -Namespace $RootNs -ClassName __NAMESPACE -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    
    foreach ($Instance in $SsrsInstances) {
        # Find all versions under the instance (e.g., V13, V14, V15)
        $Versions = Get-CimInstance -Namespace "$RootNs\$Instance" -ClassName __NAMESPACE -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        
        foreach ($Version in $Versions) {
            $TargetNs = "$RootNs\$Instance\$Version\Admin"
            try {
                $ConfigObj = Get-CimInstance -Namespace $TargetNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
                $SsrsConfigs += $ConfigObj
                if ($DebugMode) { Write-Output "Discovered SSRS Namespace: $TargetNs" }
            } catch {
                if ($DebugMode) { Write-Output "No ConfigurationSetting found in $TargetNs" }
            }
        }
    }
}

if (-not $SsrsConfigs) {
    Write-Error "No SSRS or PBIRS instances found on this server."
    return
}

$Port = 443
$SystemLocale = Get-Culture 

# 5. Process Each Discovered SSRS Instance
foreach ($Config in $SsrsConfigs) {
    Write-Output "`n=== Processing SSRS Instance: $($Config.InstanceName) ==="
    
    if ($DebugMode) { 
        Write-Output " IsInitialized : $($Config.IsInitialized)" 
        Write-Output " ServiceName   : $($Config.ServiceName)" 
    }

    $Success = $false

    foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) { 
        Write-Output "-> Application: $App"

        # Reserve URLs
        foreach ($Name in $DnsNames) { 
            $Url = "https://$Name`:$Port" 
            try { 
                $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{ Application = $App; UrlString = $Url; Lcid = $SystemLocale.LCID } -ErrorAction Stop 
                
                if ($Result.HRESULT -eq 0) {
                    Write-Output "   ReserveURL $Url → Success (0)"
                    $Success = $true
                } elseif ($Result.HRESULT -eq -2147220932) {
                    Write-Output "   ReserveURL $Url → Already Reserved (OK)"
                    $Success = $true
                } else {
                    Write-Output "   ReserveURL $Url → HRESULT: $($Result.HRESULT)"
                }
            } catch { 
                Write-Warning "   ReserveURL failed for $Url : $($_.Exception.Message)" 
            } 
        }

        # Remove Old SSL Binding
        if ($OldCertHash) {
            try {
                $Result = $Config | Invoke-CimMethod -MethodName RemoveSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $OldCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -ErrorAction Stop
                Write-Output "   RemoveSSLCertificateBinding (Old Cert) → HRESULT: $($Result.HRESULT)"
            } catch {
                Write-Output "   RemoveSSLCertificateBinding: No old binding found or removal failed."
            }
        }

        # Create New SSL Binding 
        try { 
            $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $NewCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -ErrorAction Stop 
            Write-Output "   CreateSSLCertificateBinding (New Cert) → HRESULT: $($Result.HRESULT)" 
            if ($Result.HRESULT -eq 0) { $Success = $true } 
        } catch { 
            Write-Warning "   CreateSSLCertificateBinding failed: $($_.Exception.Message)" 
        } 
    }

    # Initialize Server (If necessary)
    if (-not $Config.IsInitialized) { 
        try {
            Write-Output "Initializing Report Server..." 
            $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{ InstallationID = $Config.InstallationID } | Out-Null 
            Write-Output "✓ Initialization completed."
        } catch {
            Write-Warning "Failed to initialize server: $($_.Exception.Message)"
        }
    } 

    # 6. Restart Target Service to Apply Bindings
    if ($Success) { 
        $TargetService = $Config.ServiceName
        if (-not $TargetService) { $TargetService = 'SQLServerReportingServices' } # Fallback

        Write-Output "Restarting '$TargetService' service to apply bindings..." 
        try {
            Restart-Service -Name $TargetService -Force -ErrorAction Stop
            Write-Output "✓ Service restarted successfully." 
        } catch {
            Write-Warning "Failed to restart service '$TargetService'. You may need to restart it manually. Error: $($_.Exception.Message)"
        }
    }
}
# Finalize Task Success
if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
Write-Output "`nUniversal SSRS certificate auto-renewal and rebind processing completed."
