<#
.SYNOPSIS 
    SSRS Certificate Auto-Renewal & Auto-Rebind Handler 
    Targeted for SSRS Namespace: ROOT\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin
#>
Param( 
    [String]$OldCertHash, 
    [Parameter(Mandatory=$true)][String]$NewCertHash, 
    [Int32]$EventRecordId, 
    [switch]$DebugMode = $true
)

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

$OldCertHash = $OldCertHash?.ToUpper()
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

# 3. Filter by Certificate Template OID 
# 1.3.6.1.4.1.311.21.7 is the Certificate Template Information OID.
$certTemplateExtension = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }

if (-not $certTemplateExtension) { 
    Write-Output "No Template Information OID found on certificate. Skipping." 
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force } 
    return
} 
# Alternatively, if you need to match the specific template name/OID (e.g. "Internal Web Server" OID), 
# you can parse the raw data. Assuming the script targets specific templates, the above catches the enterprise PKI presence.

# 4. Connect to SSRS WMI Namespace
$AdminNs = "root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin"
$Port = 443

if ($DebugMode) { Write-Output "Using fixed namespace: $AdminNs" }

try { 
    $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop  
    if ($DebugMode) { 
        Write-Output "✓ Successfully connected to ConfigurationSetting" 
        Write-Output " MachineName   : $($Config.MachineName)" 
        Write-Output " IsInitialized : $($Config.IsInitialized)" 
        Write-Output " InstanceName  : $($Config.InstanceName)" 
    }

    $SystemLocale = Get-Culture 
    $Success = $false

    foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) { 
        Write-Output "Processing application: $App"

        # Reserve URLs
        foreach ($Name in $DnsNames) { 
            $Url = "https://$Name`:$Port" 
            try { 
                $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{ Application = $App; UrlString = $Url; Lcid = $SystemLocale.LCID } -ErrorAction Stop 
                Write-Output "  ReserveURL $Url → HRESULT: $($Result.HRESULT)" 
                if ($Result.HRESULT -eq 0) { $Success = $true } 
            } catch { 
                Write-Warning "  ReserveURL failed for $Url : $($_.Exception.Message)" 
            } 
        }

        # Remove Old SSL Binding (SSRS requires removing the old binding before binding a new cert to 0.0.0.0:443)
        if ($OldCertHash) {
            try {
                $Result = $Config | Invoke-CimMethod -MethodName RemoveSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $OldCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -ErrorAction Stop
                Write-Output "  RemoveSSLCertificateBinding (Old Cert) → HRESULT: $($Result.HRESULT)"
            } catch {
                Write-Output "  RemoveSSLCertificateBinding: No old binding found or removal failed."
            }
        }

        # Create New SSL Binding 
        try { 
            $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{ Application = $App; CertificateHash = $NewCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID } -ErrorAction Stop 
            Write-Output "
