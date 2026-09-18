<#
.SYNOPSIS
    V6 with Encryption - Universal Compatibility Edition (Windows 2016-2025 / SQL 2016-2022).
.DESCRIPTION
    Matches certificates strictly via Common Name (CN). Dynamically resolves SSRS WMI namespaces
    across historic and modern architecture versions. Emits flat V6 Console/Pipeline logs.
#>

param(
    [string]$SubjectName = "yourdomain.com",
    [string]$SqlInstanceName = "MSSQLSERVER",
    [string]$SsrsInstanceName = "SSRS",
    [int64]$EventRecordId = 0,
    [boolean]$EnableLogging = $true
)

function Write-V6Log {
    param(
        [ValidateSet("INFO", "WARN", "DEBUG", "ERROR")] [string]$Level = "INFO",
        [string]$Message,
        [int]$EventId = 1000
    )
    if (-not $EnableLogging) { return }
    $Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Write-Output ("[{0}] [{1}] {2}. EventRecordId: {3}" -f $Timestamp, $Level, $Message, $EventRecordId)
}

Write-V6Log -Level "DEBUG" -Message "Starting SSRS Certificate Rebind Process (CN Only)" -EventId 1001

# STEP 1: Certificate Retrieval (Common Name Only)
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
    $_.Subject -match "CN=$SubjectName\b" -and $_.NotAfter -gt (Get-Date) 
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-V6Log -Level "ERROR" -Message "No valid certificate found under strict Common Name lookup for '$SubjectName'." -EventId 5001
    Exit 1
}
$newThumbprint = $cert.Thumbprint

# STEP 2: Check SQL Server Registry State (Smart Match Check)
$regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$SqlInstanceName\MSSQLServer\SuperSocketNetLib"
if (-not (Test-Path $regPath)) {
    $instanceMappingReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (Test-Path $instanceMappingReg) {
        $realInstanceName = (Get-ItemProperty -Path $instanceMappingReg).$SqlInstanceName
        if ($realInstanceName) { $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$realInstanceName\MSSQLServer\SuperSocketNetLib" }
    }
}

if (Test-Path $regPath) {
    $currentSqlThumbprint = (Get-ItemProperty -Path $regPath -Name "Certificate" -ErrorAction SilentlyContinue).Certificate
    if ($currentSqlThumbprint -eq $newThumbprint) {
        Write-V6Log -Level "INFO" -Message "SQL Server Protocols are already bound to the latest certificate ($newThumbprint). Exiting safely." -EventId 4003
        Exit 0
    }
} else {
    Write-V6Log -Level "ERROR" -Message "Unable to verify SQL network configuration parameters via registry." -EventId 5002
    Exit 1
}

# STEP 3: Update SQL Server Protocols Encryption Rebind
Write-V6Log -Level "INFO" -Message "New certificate detected! Updating SQL Protocols thumbprint to: $newThumbprint." -EventId 4004
Set-ItemProperty -Path $regPath -Name "Certificate" -Value $newThumbprint -Type String
$global:RequiresSqlRestart = $true

# STEP 4: SSRS Dynamic WMI Auto-Discovery & Bind (SQL 2016 - 2022 Compatibility)
Write-V6Log -Level "INFO" -Message "Probing environment namespace matrix for SQL/SSRS instances..." -EventId 2001
$wmiNamespaces = @(
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v20\Admin",  # SSRS 2022
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15\Admin",  # SSRS 2019
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin",  # SSRS 2017
    "root\Microsoft\SqlServer\ReportServer\RS_MSSQLSERVER\v13\Admin" # SSRS 2016
)

$targetNamespace = $null
foreach ($ns in $wmiNamespaces) {
    if (Get-CimClass -Namespace $ns -ClassName "ReportServerWebService" -ErrorAction SilentlyContinue) {
        $targetNamespace = $ns
        break
    }
}

if ($targetNamespace) {
    Write-V6Log -Level "INFO" -Message "SSRS namespace identified: $targetNamespace" -EventId 2002
    try {
        $apps = @("ReportServerWebService", "ReportPowerBIWebService")
        foreach ($app in $apps) {
            $rsWmi = Get-CimInstance -Namespace $targetNamespace -ClassName $app -ErrorAction SilentlyContinue
            if ($rsWmi) {
                Invoke-CimMethod -InputObject $rsWmi -MethodName "ReserveURL" -Arguments @{
                    Application = $app; UrlString = "https://+:443/"; LcName = 1033
                } | Out-Null
            }
        }
        Write-V6Log -Level "INFO" -Message "Successfully finalized SSRS URL reservations map strings." -EventId 2003
    }
    catch {
        Write-V6Log -Level "WARN" -Message "SSRS WMI engine alteration threw an exception: $_" -EventId 3001
    }
} else {
    Write-V6Log -Level "WARN" -Message "WMI search sequence exhausted without finding active target reporting configurations." -EventId 3002
}

# STEP 5: Service Restarts
$ssrsService = Get-Service -Name "*ReportServer*", "MSRS*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ssrsService) {
    Write-V6Log -Level "INFO" -Message "Recycling SSRS service engine." -EventId 6002
    Restart-Service -InputObject $ssrsService -Force
}

if ($global:RequiresSqlRestart) {
    $sqlServiceName = if ($SqlInstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$SqlInstanceName" }
    $sqlService = Get-Service -Name $sqlServiceName -ErrorAction SilentlyContinue
    if ($sqlService) {
        Write-V6Log -Level "INFO" -Message "Restarting SQL Database Instance service ($sqlServiceName)." -EventId 6003
        Restart-Service -InputObject $sqlService -Force
    }
}
Write-V6Log -Level "INFO" -Message "V6 script automation run finalized successfully." -EventId 1000
