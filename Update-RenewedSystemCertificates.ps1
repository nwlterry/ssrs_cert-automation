# Updated version with full error handling
<#
.SYNOPSIS
    Update renewed certificates for SSRS (and optionally others).
    Handles Replace events from Certificate Services lifecycle notifications.

.NOTES
    Fixes: Web Portal URL "UNKNOWN" + invalid CIM class errors.
    Supports SSRS 2016–2022+ (v13–v16 namespaces).
    Full CIM error handling added.
#>

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)][String]$NewCertHash,
    [Int32]$EventRecordId
)

# === Duplicate prevention ===
$StatePath = "$env:ProgramData\CertificateNotificationTasks"
$StateFile = Join-Path $StatePath "LastProcessedEventRecordId.txt"

if ($EventRecordId) {
    if (-not (Test-Path $StatePath)) { 
        New-Item -ItemType Directory -Path $StatePath -Force | Out-Null 
    }
    $LastId = if (Test-Path $StateFile) { Get-Content $StateFile -EA SilentlyContinue } else { 0 }
    if ($EventRecordId -le $LastId) {
        Write-Output "Event $EventRecordId already processed. Exiting."
        return
    }
}

$OldCertHash = $OldCertHash?.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $NewCertHash }
if (-not $NewCertificate) { 
    throw "New certificate with thumbprint $NewCertHash not found in LocalMachine\My store." 
}

# === Extract DNS names (CN + SAN) ===
$DnsNames = @()
$SanExt = $NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
if ($SanExt) {
    $DnsNames += ($SanExt.Format(1) -split "`n" | Where-Object { $_ -match '^DNS Name=' } | ForEach-Object { ($_ -replace '^DNS Name=', '').Trim() })
}
if (-not $DnsNames -and $NewCertificate.Subject -match 'CN=([^,]+)') {
    $DnsNames += $Matches[1].Trim()
}
if (-not $DnsNames) { 
    throw "Could not extract any DNS names from the certificate." 
}

# === Filter for Internal Web Server certificates ===
if (-not ($NewCertificate.Extensions | Where-Object { 
    $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "Internal Web Server" 
})) {
    Write-Output "Certificate is not 'Internal Web Server' template. Skipping SSRS update."
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
    return
}

# === SSRS Processing with full error handling ===
$SSRSInstances = Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer -ClassName MSReportServer_Instance -ErrorAction SilentlyContinue

if (-not $SSRSInstances) {
    Write-Warning "No SSRS instances found via CIM. SSRS may not be installed or WMI namespace is unavailable."
} else {
    foreach ($Instance in $SSRSInstances) {
        Write-Output "=== Processing SSRS Instance: $($Instance.InstanceName) ==="

        try {
            # Auto-detect correct version namespace (v13 to v16)
            $AdminNs = $null
            foreach ($v in 16..13) {
                $Candidate = "root\Microsoft\SqlServer\ReportServer\RS_$($Instance.InstanceName)\v$v\Admin"
                try {
                    if (Get-CimInstance -Namespace $Candidate -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop) {
                        $AdminNs = $Candidate
                        break
                    }
                } catch { }
            }

            if (-not $AdminNs) {
                Write-Warning "Could not find supported SSRS Admin namespace for instance $($Instance.InstanceName). Skipping."
                continue
            }

            Write-Output "Using namespace: $AdminNs"

            # Get Configuration
            $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop

            # Get supporting objects
            $Reserved = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ReservedURL -ErrorAction SilentlyContinue
            $Bindings  = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_SSLCertificateBinding -ErrorAction SilentlyContinue

            $SystemLocale = Get-Culture
            $SuccessCount = 0

            foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) {
                Write-Output "  Processing application: $App"

                # --- Reserve URLs (fixes UNKNOWN WebAccess) ---
                $Port = 443  # Change if you use a custom port
                foreach ($Name in $DnsNames) {
                    $Url = "https://$Name`:$Port"
                    try {
                        $Result = $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{
                            Application = $App
                            UrlString   = $Url
                            Lcid        = $SystemLocale.LCID
                        } -ErrorAction Stop

                        if ($Result.HRESULT -eq 0) {
                            Write-Output "    Reserved URL: $Url"
                            $SuccessCount++
                        } else {
                            Write-Warning "    ReserveURL returned HRESULT $($Result.HRESULT) for $Url"
                        }
                    }
                    catch {
                        Write-Warning "    Failed to reserve URL $Url for $App : $($_.Exception.Message)"
                    }
                }

                # --- Update Certificate Binding ---
                if ($OldCertHash) {
                    $OldBindings = $Bindings | Where-Object { $_.Application -eq $App -and $_.CertificateHash -eq $OldCertHash }
                    foreach ($b in $OldBindings) {
                        try {
                            $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                                Application     = $App
                                CertificateHash = $NewCertHash.ToLower()
                                IPAddress       = $b.IPAddress
                                Port            = $b.Port
                                Lcid            = $SystemLocale.LCID
                            } -ErrorAction Stop

                            if ($Result.HRESULT -eq 0) {
                                Write-Output "    Updated SSL binding for $App on $($b.IPAddress):$($b.Port)"
                                $SuccessCount++
                            } else {
                                Write-Warning "    CreateSSLCertificateBinding returned HRESULT $($Result.HRESULT)"
                            }
                        }
                        catch {
                            Write-Warning "    Failed to update binding for $App : $($_.Exception.Message)"
                        }
                    }
                }
            }

            # --- Initialize and set URLs (critical for Web Portal) ---
            try {
                if (-not $Config.IsInitialized) {
                    $InitResult = $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{
                        InstallationID = $Config.InstallationID
                    } -ErrorAction Stop
                    Write-Output "    ReportServer initialized."
                }

                $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{
                    Protocol = 'https'
                    HostName = $Config.MachineName
                    Port     = $Config.WebServicePort
                    VirtualDirectory = $Config.WebServiceVirtualDirectory
                } -ErrorAction Stop | Out-Null

                $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{
                    Protocol = 'https'
                    HostName = $Config.MachineName
                    Port     = $Config.WebPortalPort
                    VirtualDirectory = $Config.WebPortalVirtualDirectory
                } -ErrorAction Stop | Out-Null

                Write-Output "    WebServiceUrl and WebPortalUrl successfully updated."
                $SuccessCount++
            }
            catch {
                Write-Warning "    Failed to set Web URLs or initialize: $($_.Exception.Message)"
            }

            if ($SuccessCount -gt 0) {
                Write-Output "  Restarting SQLServerReportingServices service..."
                Restart-Service -Name 'SQLServerReportingServices' -Force -ErrorAction Stop
                Write-Output "  SSRS service restarted successfully."
            }
        }
        catch {
            Write-Error "Critical error processing SSRS instance $($Instance.InstanceName): $($_.Exception.Message)" -ErrorAction Continue
        }
    }
}

# Update last processed event
if ($EventRecordId) {
    Set-Content -Path $StateFile -Value $EventRecordId -Force
}

Write-Output "`nSSRS certificate renewal processing completed."