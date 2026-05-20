<#
.SYNOPSIS
    Update renewed system certificates and re-bind dependent services including
    SQL Server Reporting Services (SSRS).

.DESCRIPTION
    Handles AD CS lifecycle notifications using EventRecordId.
    Supports SSRS 2016, 2017, 2019, and 2022.
    Prevents SSRS Web Service / Portal URL from showing UNKNOWN.

.NOTES
    Based on:
    https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

    Original script:
    https://github.com/Borgquite/CertificateNotificationTasks
#>

Param(
    [String]$OldCertHash,

    [Parameter(Mandatory = $true)]
    [String]$NewCertHash,

    [Int32]$EventRecordId
)

# ====================================================================
# === EVENT RECORD ID HANDLING =======================================
# ====================================================================

$StatePath = "$env:ProgramData\CertificateNotificationTasks"
$StateFile = Join-Path $StatePath "LastProcessedEventRecordId.txt"

if ($EventRecordId) {

    if (-not (Test-Path $StatePath)) {
        New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
    }

    $LastProcessedId = if (Test-Path $StateFile) {
        Get-Content $StateFile -ErrorAction SilentlyContinue
    } else {
        0
    }

    if ($EventRecordId -le $LastProcessedId) {
        Write-Output "EventRecordId $EventRecordId already processed (last: $LastProcessedId). Exiting."
        return
    }

    Write-Output "Processing EventRecordId $EventRecordId (last processed: $LastProcessedId)"
}

# ====================================================================
# === CERTIFICATE RESOLUTION ========================================
# ====================================================================

$OldCertHash = $OldCertHash?.ToUpper()
$NewCertHash = $NewCertHash.ToUpper()
$SystemLocale = Get-Culture

$NewCertificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Thumbprint -eq $NewCertHash }

if (-not $NewCertificate) {
    throw "New certificate with thumbprint '$NewCertHash' not found."
}

# ====================================================================
# === CN-FIRST, SAN-OPTIONAL DNS RESOLUTION ==========================
# ====================================================================

$CertificateDnsNames = @()

$SanExtension = $NewCertificate.Extensions |
    Where-Object { $_.Oid.Value -eq '2.5.29.17' } |
    Select-Object -First 1

if ($SanExtension) {
    $CertificateDnsNames += (
        $SanExtension.Format(1) -split [System.Environment]::NewLine |
        Where-Object { $_ -match '^DNS Name=' } |
        ForEach-Object { $_ -replace '^DNS Name=', '' }
    )
}

if (-not $CertificateDnsNames.Count -and $NewCertificate.Subject -match 'CN=([^,]+)') {
    $CertificateDnsNames += $Matches[1]
}

if (-not $CertificateDnsNames.Count) {
    throw "Unable to resolve DNS names from certificate CN or SAN."
}

# ====================================================================
# === SSRS INSTANCE DISCOVERY (SSRS 2016+) ===========================
# ====================================================================

$SSRSInstances = Get-CimInstance `
    -Namespace root\Microsoft\SqlServer\ReportServer `
    -ClassName MSReportServer_Instance

foreach ($Instance in $SSRSInstances) {

    Write-Output "Processing SSRS instance: $($Instance.InstanceName)"

    # === NEW: Auto-detect SSRS WMI Admin version (v13–v16)
    $AdminNamespace = $null
    foreach ($Version in 16..13) {
        $Candidate = "root\Microsoft\SqlServer\ReportServer\RS_$($Instance.InstanceName)\v$Version\Admin"
        if (Get-CimInstance -Namespace $Candidate -ClassName MSReportServer_ConfigurationSetting -ErrorAction SilentlyContinue) {
            $AdminNamespace = $Candidate
            Write-Output "Using SSRS WMI namespace: $AdminNamespace"
            break
        }
    }

    if (-not $AdminNamespace) {
        Write-Warning "No supported SSRS Admin namespace found for $($Instance.InstanceName). Skipping."
        continue
    }

    $Config = Get-CimInstance -Namespace $AdminNamespace -ClassName MSReportServer_ConfigurationSetting
    $ReservedUrls = Get-CimInstance -Namespace $AdminNamespace -ClassName MSReportServer_ReservedURL
    $SslBindings = Get-CimInstance -Namespace $AdminNamespace -ClassName MSReportServer_SSLCertificateBinding

    foreach ($App in 'ReportServerWebService', 'ReportServerWebApp') {

        $Port = (
            $ReservedUrls |
            Where-Object { $_.Application -eq $App -and $_.UrlString -match '^https://' } |
            Select-Object -First 1 |
            ForEach-Object { ($_ -split ':')[-1] }
        )

        if (-not $Port) { continue }

        foreach ($DnsName in $CertificateDnsNames) {

            $Url = "https://$DnsName:$Port"
            $Config | Invoke-CimMethod -MethodName ReserveURL -Arguments @{
                Application = $App
                UrlString  = $Url
                Lcid       = $SystemLocale.LCID
            } | Out-Null
        }

        if ($OldCertHash) {
            for ($i = 0; $i -lt $SslBindings.Application.Count; $i++) {
                if ($SslBindings.Application[$i] -eq $App -and
                    $SslBindings.CertificateHash[$i] -eq $OldCertHash) {

                    $Config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                        Application     = $App
                        CertificateHash = $NewCertHash.ToLower()
                        IPAddress       = $SslBindings.IPAddress[$i]
                        Port            = $SslBindings.Port[$i]
                        Lcid            = $SystemLocale.LCID
                    } | Out-Null
                }
            }
        }
    }

    # =================================================================
    # === COMMIT CONFIGURATION (CRITICAL FOR ALL SSRS 2016+) ==========
    # =================================================================

    if (-not $Config.IsInitialized) {
        $Config | Invoke-CimMethod -MethodName InitializeReportServer -Arguments @{
            InstallationID = $Config.InstallationID
        } | Out-Null
    }

    $Config | Invoke-CimMethod -MethodName SetWebServiceUrl -Arguments @{
        Protocol         = 'https'
        HostName         = $Config.MachineName
        Port             = $Config.WebServicePort
        VirtualDirectory = $Config.WebServiceVirtualDirectory
    } | Out-Null

    $Config | Invoke-CimMethod -MethodName SetWebPortalUrl -Arguments @{
        Protocol         = 'https'
        HostName         = $Config.MachineName
        Port             = $Config.WebPortalPort
        VirtualDirectory = $Config.WebPortalVirtualDirectory
    } | Out-Null

    Restart-Service SQLServerReportingServices -Force
}

# ====================================================================
# === UPDATE EVENT STATE =============================================
# ====================================================================

if ($EventRecordId) {
    Set-Content -Path $StateFile -Value $EventRecordId -Force
}

Write-Output "Certificate renewal processing completed successfully."
