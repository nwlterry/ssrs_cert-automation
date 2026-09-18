<#
.SYNOPSIS
    V5 with Encryption - Universal Compatibility Edition (Windows 2016-2025 / SQL 2016-2022).
.DESCRIPTION
    Matches certificates via CN + SAN fields. Dynamically resolves SSRS WMI namespaces
    across historic and modern architecture versions. Emits nested V5 JSON logs.
#>

param(
    [string]$SubjectName = "yourdomain.com",
    [string]$SqlInstanceName = "MSSQLSERVER",
    [string]$SsrsInstanceName = "SSRS",
    [int64]$EventRecordId = 0,
    [boolean]$EnableLogging = $true
)

function Write-V5Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR")] [string]$Level = "INFO",
        [string]$Message,
        [int]$EventId = 1000
    )
    if (-not $EnableLogging) { return }
    $LogPayload = [ordered]@{
        "LogHeader" = @{
            "Timestamp"  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            "SchemaVer"  = "5.0"
            "Severity"   = $Level
        }
        "EventData" = @{
            "Id"         = $EventId
            "Source"     = "SSRS_SQL_V5_Automation"
            "Message"    = "$Message (EventRecordId: $EventRecordId)"
        }
    }
    Write-Output ($LogPayload | ConvertTo-Json -Compress)
}

# STEP 1: Certificate Retrieval (CN + SAN Strategy)
Write-V5Log -Message "Scanning for certificate matching CN or SAN: $SubjectName" -EventId 1001
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.NotAfter -gt (Get-Date) -and (
        $_.Subject -match "CN=$SubjectName" -or 
        ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } | 
          Select-Object -ExpandProperty Format -ErrorAction SilentlyContinue) -match $SubjectName
    )
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-V5Log -Level "ERROR" -Message "No valid certificate found matching CN or SAN for '$SubjectName'." -EventId 5001
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
        Write-V5Log -Message "SQL Network Configuration matches ($newThumbprint). Execution bypassed." -EventId 4003
        Exit 0
    }
} else {
    Write-V5Log -Level "ERROR" -Message "Failed to locate SQL Server network registry configuration." -EventId 5002
    Exit 1
}

# STEP 3: Update SQL Server Protocols Encryption Rebind
Write-V5Log -Message "New certificate detected. Updating SQL Protocols thumbprint to: $newThumbprint" -EventId 4004
Set-ItemProperty -Path $regPath -Name "Certificate" -Value $newThumbprint -Type String
$global:RequiresSqlRestart = $true

# STEP 4: SSRS Dynamic WMI Auto-Discovery & Bind (SQL 2016 - 2022 Compatibility)
Write-V5Log -Message "Scanning for valid SSRS WMI Namespaces..." -EventId 2001
$wmiNamespaces = @(
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v20\Admin",  # SSRS 2022
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15\Admin",  # SSRS 2019
    "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin",  # SSRS 2017
    "root\Microsoft\SqlServer\ReportServer\RS_MSSQLSERVER\v13\Admin" # SSRS 2016 (Legacy)
)

$targetNamespace = $null
foreach ($ns in $wmiNamespaces) {
    if (Get-CimClass -Namespace $ns -ClassName "ReportServerWebService" -ErrorAction SilentlyContinue) {
        $targetNamespace = $ns
        break
    }
}

if ($targetNamespace) {
    Write-V5Log -Message "Resolved operational target namespace: $targetNamespace" -EventId 2002
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
        Write-V5Log -Message "Successfully updated SSRS web URL allocations via WMI." -EventId 2003
    }
    catch {
        Write-V5Log -Level "WARN" -Message "SSRS WMI modification error occurred: $_" -EventId 3001
    }
} else {
    Write-V5Log -Level "WARN" -Message "No known SSRS WMI instances discovered locally. Binding adjustments skipped." -EventId 3002
}

# STEP 5: Service Management Controls
$ssrsService = Get-Service -Name "*ReportServer*", "MSRS*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ssrsService) {
    Write-V5Log -Message "Recycling SSRS service core." -EventId 6002
    Restart-Service -InputObject $ssrsService -Force
}

if ($global:RequiresSqlRestart) {
    $sqlServiceName = if ($SqlInstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$SqlInstanceName" }
    $sqlService = Get-Service -Name $sqlServiceName -ErrorAction SilentlyContinue
    if ($sqlService) {
        Write-V5Log -Message "Restarting SQL Engine ($sqlServiceName)." -EventId 6003
        Restart-Service -InputObject $sqlService -Force
    }
}
Write-V5Log -Message "V5 script configuration process finalized." -EventId 1000
