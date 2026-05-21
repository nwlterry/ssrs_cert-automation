<#
.SYNOPSIS
    SSRS Certificate Auto-Renewal Handler
    Optimized for your exact namespace: ROOT\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin
#>

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)][String]$NewCertHash,
    [Int32]$EventRecordId,
    [switch]$DebugMode = $true
)

if ($DebugMode) { Write-Output "=== DEBUG MODE ENABLED ===" }

# Duplicate prevention
$StatePath = "$env:ProgramData\CertificateNotificationTasks"
$StateFile = Join-Path $StatePath "LastProcessedEventRecordId.txt"

if ($EventRecordId) {
    if (-not (Test-Path $StatePath)) { New-Item -ItemType Directory -Path $StatePath -Force | Out-Null }
    $LastId = if (Test-Path $StateFile) { Get-Content $StateFile -EA SilentlyContinue } else { 0 }
    if ($EventRecordId -le $LastId) { 
        Write-Output "Event already processed. Exiting."
        return 
    }
}

$OldCertHash = $OldCertHash?.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { throw "New certificate $NewCertHash not found." }

if ($DebugMode) {
    Write-Output "New Cert Subject : $($NewCertificate.Subject)"
}

# Extract DNS Names
$DnsNames = @()
$SanExt = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
if ($SanExt) {
    $DnsNames += ($SanExt.Format(1) -split "`n" | Where-Object { $_ -match '^DNS Name=' } | ForEach-Object { ($_ -replace '^DNS Name=', '').Trim() })
}
if (-not $DnsNames -and $NewCertificate.Subject -match 'CN=([^,]+)') {
    $DnsNames += $Matches[1].Trim()
}
if ($DebugMode) { Write-Output "DNS Names: $($DnsNames -join ', ')" }

# Only Internal Web Server cert
if (-not ($NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "Internal Web Server" })) {
    Write-Output "Not an Internal Web Server certificate. Skipping."
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
    return
}

# === Your Exact Namespace ===
$AdminNs = "root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin"
$Port = 443

if ($DebugMode) { Write-Output "Using fixed namespace: $AdminNs" }

try {
    $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
    
    if ($DebugMode) {
        Write-Output "✓ Successfully connected to ConfigurationSetting"
        Write-Output "  MachineName     : $($Config.MachineName)"
        Write-Output "  IsInitialized   : $($Config.IsInitialized)"
        Write-Output "  InstanceName    : $($Config.InstanceName)"
    }

    $SystemLocale = Get-Culture
    $Success = $false

    foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) {
        Write-Output "Processing application: $App"

        # Reserve URLs (Critical for fixing UNKNOWN)
        foreach ($Name in $DnsNames) {
            $Url = "https://$Name`:$Port"
            try {
                $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{
                    Application = $App
                    UrlString   = $Url
                    Lcid        = $SystemLocale.LCID
                } -ErrorAction Stop
                Write-Output "  ReserveURL $Url → HRESULT: $($Result.HRESULT)"
                if ($Result.HRESULT -eq 0) { $Success = $true }
            } catch {
                Write-Warning "  ReserveURL failed for $Url : $($_.Exception.Message)"
            }
        }

        # Create SSL Binding
        if ($OldCertHash) {
            try {
                $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                    Application     = $App
                    CertificateHash = $NewCertHash.ToLower()
                    IPAddress       = '0.0.0.0'
                    Port            = $Port
                    Lcid            = $SystemLocale.LCID
                } -ErrorAction Stop
                Write-Output "  CreateSSLCertificateBinding → HRESULT: $($Result.HRESULT)"
                if ($Result.HRESULT -eq 0) { $Success = $true }
            } catch {
                Write-Warning "  CreateSSLCertificateBinding failed: $($_.Exception.Message)"
            }
        }
    }

    # Set Web URLs
    try {
        if (-not $Config.IsInitialized) {
            Write-Output "Initializing Report Server..."
            $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{ InstallationID = $Config.InstallationID } | Out-Null
        }
        $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{
            Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebServiceVirtualDirectory
        } | Out-Null

        $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{
            Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebPortalVirtualDirectory
        } | Out-Null

        Write-Output "✓ WebServiceUrl and WebPortalUrl updated successfully."
        $Success = $true
    } catch {
        Write-Warning "Failed to set Web URLs: $($_.Exception.Message)"
    }

    if ($Success) {
        Write-Output "Restarting SQLServerReportingServices service..."
        Restart-Service -Name 'SQLServerReportingServices' -Force
        Write-Output "Service restarted."
    }
}
catch {
    Write-Error "Failed to connect or process SSRS configuration: $($_.Exception.Message)"
    Write-Output "Please verify the namespace '$AdminNs' is correct on this server."
}

if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
Write-Output "`nSSRS certificate renewal processing completed."
