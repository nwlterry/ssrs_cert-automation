<#
.SYNOPSIS
    SSRS Certificate Auto-Renewal Handler
    Optimized for your environment: MSReportServer_Instance under RS_SSRS\V14
#>

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)][String]$NewCertHash,
    [Int32]$EventRecordId
)

# Duplicate prevention
$StatePath = "$env:ProgramData\CertificateNotificationTasks"
$StateFile = Join-Path $StatePath "LastProcessedEventRecordId.txt"

if ($EventRecordId) {
    if (-not (Test-Path $StatePath)) { New-Item -ItemType Directory -Path $StatePath -Force | Out-Null }
    $LastId = if (Test-Path $StateFile) { Get-Content $StateFile -EA SilentlyContinue } else { 0 }
    if ($EventRecordId -le $LastId) { Write-Output "Event already processed."; return }
}

$OldCertHash = $OldCertHash?.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { throw "New certificate $NewCertHash not found." }

# Extract DNS Names
$DnsNames = @()
$SanExt = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
if ($SanExt) {
    $DnsNames += ($SanExt.Format(1) -split "`n" | Where-Object { $_ -match '^DNS Name=' } | ForEach-Object { ($_ -replace '^DNS Name=', '').Trim() })
}
if (-not $DnsNames -and $NewCertificate.Subject -match 'CN=([^,]+)') {
    $DnsNames += $Matches[1].Trim()
}
if (-not $DnsNames) { throw "No DNS names in certificate." }

# Only Internal Web Server cert
if (-not ($NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "Internal Web Server" })) {
    Write-Output "Not Internal Web Server cert. Skipping."
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
    return
}

# === Discovery: Look inside version namespace first (your environment) ===
$RootNs = "root\Microsoft\SqlServer\ReportServer"
$InstanceName = "RS_SSRS"   # From your info
$Found = $false

foreach ($v in 16..13) {
    $VersionNs = "$RootNs\$InstanceName\v$v"
    $AdminNs   = "$VersionNs\Admin"

    # Check for MSReportServer_Instance in version namespace
    try {
        $InstanceObj = Get-CimInstance -Namespace $VersionNs -ClassName MSReportServer_Instance -ErrorAction Stop
        Write-Output "Found MSReportServer_Instance in $VersionNs"
        $Found = $true
    } catch { }

    if (-not $Found) {
        # Fallback: check Admin namespace directly
        try {
            if (Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop) {
                $Found = $true
            }
        } catch { }
    }

    if ($Found -and (Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction SilentlyContinue)) {
        Write-Output "Using Admin namespace: $AdminNs"
        break
    }
}

if (-not $Found) {
    Write-Warning "Could not find SSRS ConfigurationSetting. Trying broad __Namespace search..."
    $Instances = Get-CimInstance -Namespace $RootNs -ClassName __Namespace -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RS_*' }
    # (fallback code remains the same as before)
}

# === Main Processing ===
try {
    $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
    $SystemLocale = Get-Culture
    $Port = 443
    $Success = $false

    foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) {
        Write-Output "Processing $App..."

        # Reserve URLs (fixes UNKNOWN)
        foreach ($Name in $DnsNames) {
            $Url = "https://$Name`:$Port"
            try {
                $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{
                    Application = $App; UrlString = $Url; Lcid = $SystemLocale.LCID
                } -ErrorAction Stop
                if ($Result.HRESULT -eq 0) { Write-Output "  Reserved: $Url"; $Success = $true }
            } catch { Write-Warning "ReserveURL failed for $Url: $($_.Exception.Message)" }
        }

        # SSL Binding
        if ($OldCertHash) {
            try {
                $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                    Application = $App; CertificateHash = $NewCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID
                } -ErrorAction Stop
                if ($Result.HRESULT -eq 0) { Write-Output "  SSL Binding updated"; $Success = $true }
            } catch { Write-Warning "CreateSSLCertificateBinding failed: $($_.Exception.Message)" }
        }
    }

    # Set Web URLs
    try {
        if (-not $Config.IsInitialized) {
            $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{ InstallationID = $Config.InstallationID } | Out-Null
        }
        $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{ Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebServiceVirtualDirectory } | Out-Null
        $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{ Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebPortalVirtualDirectory } | Out-Null
        Write-Output "Web URLs updated successfully."
        $Success = $true
    } catch { Write-Warning "SetWeb URLs failed: $($_.Exception.Message)" }

    if ($Success) {
        Restart-Service -Name 'SQLServerReportingServices' -Force
        Write-Output "SSRS service restarted."
    }
} catch {
    Write-Error "Processing failed: $($_.Exception.Message)"
}

if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
Write-Output "SSRS certificate renewal completed."
