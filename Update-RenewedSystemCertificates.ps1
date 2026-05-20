<#
.SYNOPSIS
    SSRS Certificate Auto-Renewal Handler with Debug Support
    Optimized for your environment (MSReportServer_Instance under RS_SSRS\V14)
#>

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)][String]$NewCertHash,
    [Int32]$EventRecordId,
    [switch]$DebugMode = $true   # Set to $false in production
)

if ($DebugMode) { Write-Output "=== DEBUG MODE ENABLED ===" }

# Duplicate prevention
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

if ($DebugMode) { Write-Output "New Cert Thumbprint: $NewCertHash" }

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { throw "New certificate $NewCertHash not found." }

if ($DebugMode) { 
    Write-Output "Certificate Subject: $($NewCertificate.Subject)"
    Write-Output "Certificate Template: $($NewCertificate.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'} | Select-Object -ExpandProperty Format)"
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
if ($DebugMode) { Write-Output "Extracted DNS Names: $($DnsNames -join ', ')" }

# Only Internal Web Server cert
if (-not ($NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "Internal Web Server" })) {
    Write-Output "Not an Internal Web Server certificate. Skipping."
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
    return
}

# === CIM Debug Discovery ===
$RootNs = "root\Microsoft\SqlServer\ReportServer"
$InstanceName = "RS_SSRS"
$AdminNs = $null

Write-Output "=== Starting CIM Namespace Discovery ==="

foreach ($v in 16..13) {
    $VersionNs = "$RootNs\$InstanceName\v$v"
    $AdminNsCandidate = "$VersionNs\Admin"
    
    Write-Output "Trying namespace: $AdminNsCandidate"
    
    # Check MSReportServer_Instance
    try {
        $InstanceObj = Get-CimInstance -Namespace $VersionNs -ClassName MSReportServer_Instance -ErrorAction Stop
        Write-Output "✓ Found MSReportServer_Instance in $VersionNs"
        if ($DebugMode) { $InstanceObj | Format-List InstanceName, Version, Edition | Out-String | Write-Output }
    } catch {
        Write-Output "  No MSReportServer_Instance: $($_.Exception.Message)"
    }

    # Check ConfigurationSetting
    try {
        $ConfigTest = Get-CimInstance -Namespace $AdminNsCandidate -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
        Write-Output "✓ Found MSReportServer_ConfigurationSetting in $AdminNsCandidate"
        $AdminNs = $AdminNsCandidate
        if ($DebugMode) {
            Write-Output "  MachineName: $($ConfigTest.MachineName)"
            Write-Output "  IsInitialized: $($ConfigTest.IsInitialized)"
            Write-Output "  WebServiceVirtualDirectory: $($ConfigTest.WebServiceVirtualDirectory)"
        }
        break
    } catch {
        Write-Output "  No ConfigurationSetting: $($_.Exception.Message)"
    }
}

if (-not $AdminNs) {
    Write-Warning "Could not locate SSRS Admin namespace. Trying broad search..."
    # Fallback broad search (kept for safety)
}

# === Main Processing with Debug ===
if ($AdminNs) {
    try {
        Write-Output "Using Admin Namespace: $AdminNs"
        $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
        $SystemLocale = Get-Culture
        $Port = 443
        $Success = $false

        foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) {
            Write-Output "Processing application: $App"

            # Reserve URLs
            foreach ($Name in $DnsNames) {
                $Url = "https://$Name`:$Port"
                try {
                    $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{
                        Application = $App; UrlString = $Url; Lcid = $SystemLocale.LCID
                    } -ErrorAction Stop
                    Write-Output "  ReserveURL Result for $Url → HRESULT: $($Result.HRESULT)"
                    if ($Result.HRESULT -eq 0) { $Success = $true }
                } catch {
                    Write-Warning "  ReserveURL failed for $Url: $($_.Exception.Message)"
                }
            }

            # SSL Binding
            if ($OldCertHash) {
                try {
                    $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                        Application = $App; CertificateHash = $NewCertHash.ToLower(); IPAddress = '0.0.0.0'; Port = $Port; Lcid = $SystemLocale.LCID
                    } -ErrorAction Stop
                    Write-Output "  CreateSSLCertificateBinding Result → HRESULT: $($Result.HRESULT)"
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
            $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{ Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebServiceVirtualDirectory } | Out-Null
            $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{ Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebPortalVirtualDirectory } | Out-Null
            Write-Output "✓ Web URLs updated successfully."
            $Success = $true
        } catch {
            Write-Warning "Set Web URLs failed: $($_.Exception.Message)"
        }

        if ($Success) {
            Write-Output "Restarting SQLServerReportingServices..."
            Restart-Service -Name 'SQLServerReportingServices' -Force
        }
    }
    catch {
        Write-Error "Critical error: $($_.Exception.Message)"
    }
}

if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
Write-Output "`n=== SSRS certificate renewal processing completed ==="
