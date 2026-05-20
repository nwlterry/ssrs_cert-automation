<#
.SYNOPSIS
    SSRS Certificate Auto-Renewal Handler for Windows Certificate Lifecycle Notifications
    Optimized for SSRS 2017+ (v14+) where only MSReportServer_ConfigurationSetting class exists.
#>

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)][String]$NewCertHash,
    [Int32]$EventRecordId
)

# === Duplicate Event Prevention ===
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

# === Extract DNS Names (CN + SAN) ===
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

# === Only process Internal Web Server certificates ===
if (-not ($NewCertificate.Extensions | Where-Object { 
    $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "Internal Web Server" 
})) {
    Write-Output "Certificate is not 'Internal Web Server' template. Skipping."
    if ($EventRecordId) { Set-Content -Path $StateFile -Value $EventRecordId -Force }
    return
}

# === Discover SSRS Instances via __Namespace ===
$RootNs = "root\Microsoft\SqlServer\ReportServer"
$Instances = Get-CimInstance -Namespace $RootNs -ClassName __Namespace -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'RS_*' }

if (-not $Instances) {
    Write-Warning "No SSRS instances found under $RootNs"
} else {
    foreach ($InstNs in $Instances) {
        $InstanceName = $InstNs.Name
        Write-Output "=== Processing SSRS Instance: $InstanceName ==="

        # Find correct Admin namespace (v16 down to v13)
        $AdminNs = $null
        foreach ($v in 16..13) {
            $Candidate = "$RootNs\$InstanceName\v$v\Admin"
            try {
                if (Get-CimInstance -Namespace $Candidate -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop) {
                    $AdminNs = $Candidate
                    break
                }
            } catch { }
        }

        if (-not $AdminNs) {
            Write-Warning "No supported Admin namespace found for $InstanceName. Skipping."
            continue
        }

        try {
            $Config = Get-CimInstance -Namespace $AdminNs -ClassName MSReportServer_ConfigurationSetting -ErrorAction Stop
            $SystemLocale = Get-Culture
            $Success = $false
            $Port = 443   # ← Change if you use a different HTTPS port

            foreach ($App in @('ReportServerWebService', 'ReportServerWebApp')) {
                Write-Output "  Processing application: $App"

                # Reserve URLs - Fixes "UNKNOWN" Web Portal
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
                            $Success = $true
                        }
                    } catch {
                        Write-Warning "    ReserveURL failed for $Url: $($_.Exception.Message)"
                    }
                }

                # Create SSL Certificate Binding
                if ($OldCertHash) {
                    try {
                        $Result = $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                            Application     = $App
                            CertificateHash = $NewCertHash.ToLower()
                            IPAddress       = '0.0.0.0'
                            Port            = $Port
                            Lcid            = $SystemLocale.LCID
                        } -ErrorAction Stop
                        if ($Result.HRESULT -eq 0) {
                            Write-Output "    SSL Binding updated for $App"
                            $Success = $true
                        }
                    } catch {
                        Write-Warning "    CreateSSLCertificateBinding failed: $($_.Exception.Message)"
                    }
                }
            }

            # Set Web URLs
            try {
                if (-not $Config.IsInitialized) {
                    $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{ InstallationID = $Config.InstallationID } | Out-Null
                }
                $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{
                    Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebServiceVirtualDirectory
                } | Out-Null
                $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{
                    Protocol='https'; HostName=$Config.MachineName; Port=$Port; VirtualDirectory=$Config.WebPortalVirtualDirectory
                } | Out-Null
                Write-Output "    WebServiceUrl and WebPortalUrl updated."
                $Success = $true
            } catch {
                Write-Warning "    Failed to set Web URLs: $($_.Exception.Message)"
            }

            if ($Success) {
                Write-Output "  Restarting SQLServerReportingServices service..."
                Restart-Service -Name 'SQLServerReportingServices' -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Critical error processing instance $InstanceName: $($_.Exception.Message)"
        }
    }
}

# Update last processed event
if ($EventRecordId) {
    Set-Content -Path $StateFile -Value $EventRecordId -Force
}

Write-Output "`nSSRS certificate renewal processing completed successfully."
