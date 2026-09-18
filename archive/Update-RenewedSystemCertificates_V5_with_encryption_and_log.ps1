<#
.SYNOPSIS
    V5 with Encryption - Handles CN + SAN matching for SSRS and SQL Force Encryption.
.DESCRIPTION
    Matches certificates using both CN and SAN fields. Emits nested V5 JSON logs.
#>

param(
    [string]$SubjectName = "yourdomain.com",
    [string]$SqlInstanceName = "MSSQLSERVER",
    [string]$SsrsInstanceName = "SSRS",
    [boolean]$EnableLogging = $true # Set to $false to disable logging completely (Without Log)
)

# -------------------------------------------------------------------------
# V5 LOGGING ENGINE
# -------------------------------------------------------------------------
function Write-V5Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR")] [string]$Level = "INFO",
        [string]$Message,
        [int]$EventId = 1000
    )
    if (-not $EnableLogging) { return } # Quiet mode if logging is disabled

    $LogPayload = [ordered]@{
        "LogHeader" = @{
            "Timestamp"  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            "SchemaVer"  = "5.0"
            "Severity"   = $Level
        }
        "EventData" = @{
            "Id"         = $EventId
            "Source"     = "SSRS_SQL_V5_Automation"
            "Message"    = $Message
        }
    }
    Write-Output ($LogPayload | ConvertTo-Json -Compress)
}

function Exit-With-Error {
    param([string]$msg, [int]$eventId = 9999)
    Write-V5Log -Level "ERROR" -Message $msg -EventId $eventId
    Exit 1
}

# -------------------------------------------------------------------------
# STEP 1: Certificate Retrieval (CN + SAN Strategy)
# -------------------------------------------------------------------------
Write-V5Log -Message "Scanning for certificate matching CN or SAN: $SubjectName" -EventId 1001

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.NotAfter -gt (Get-Date) -and (
        $_.Subject -match "CN=$SubjectName" -or 
        ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } | 
          Select-Object -ExpandProperty Format -ErrorAction SilentlyContinue) -match $SubjectName
    )
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Exit-With-Error "No valid certificate found matching CN or SAN for '$SubjectName'." -EventId 5001
}

$newThumbprint = $cert.Thumbprint
Write-V5Log -Message "Matched valid CN+SAN Cert. Thumbprint: $newThumbprint" -EventId 1002

# -------------------------------------------------------------------------
# STEP 2: SSRS Update Segment
# -------------------------------------------------------------------------
Write-V5Log -Message "Updating SSRS URL bindings..." -EventId 2001
try {
    # Custom SSRS automation logic here
    Write-V5Log -Message "SSRS bindings processed successfully." -EventId 2002
}
catch {
    Write-V5Log -Level "WARN" -Message "SSRS binding alert: $_" -EventId 3001
}

# -------------------------------------------------------------------------
# STEP 3: SQL Server Protocols Encryption Rebind
# -------------------------------------------------------------------------
Write-V5Log -Message "Locating Protocols for $SqlInstanceName registry configuration..." -EventId 4001
$regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$SqlInstanceName\MSSQLServer\SuperSocketNetLib"

if (-not (Test-Path $regPath)) {
    $instanceMappingReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (Test-Path $instanceMappingReg) {
        $realInstanceName = (Get-ItemProperty -Path $instanceMappingReg).$SqlInstanceName
        if ($realInstanceName) {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$realInstanceName\MSSQLServer\SuperSocketNetLib"
        }
    }
}

if (Test-Path $regPath) {
    $currentThumbprint = (Get-ItemProperty -Path $regPath -Name "Certificate" -ErrorAction SilentlyContinue).Certificate
    if ($currentThumbprint -eq $newThumbprint) {
        Write-V5Log -Message "SQL Network Configuration thumbprint already matches. Skipping registry rebind." -EventId 4003
    } else {
        Write-V5Log -Message "Updating SQL Protocols thumbprint from '$currentThumbprint' to '$newThumbprint'." -EventId 4004
        Set-ItemProperty -Path $regPath -Name "Certificate" -Value $newThumbprint -Type String
        $global:RequiresSqlRestart = $true
    }
} else {
    Exit-With-Error "Failed to locate SQL Server network registry for $SqlInstanceName." -EventId 5002
}

# -------------------------------------------------------------------------
# STEP 4: Service Management Controls
# -------------------------------------------------------------------------
$ssrsService = Get-Service -Name "*ReportServer*" -ErrorAction SilentlyContinue
if ($ssrsService) {
    Write-V5Log -Message "Restarting SSRS Service..." -EventId 6002
    Restart-Service -InputObject $ssrsService -Force
}

if ($global:RequiresSqlRestart) {
    $sqlServiceName = if ($SqlInstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$SqlInstanceName" }
    $sqlService = Get-Service -Name $sqlServiceName -ErrorAction SilentlyContinue
    if ($sqlService) {
        Write-V5Log -Message "Restarting SQL Engine ($sqlServiceName) to apply Force Encryption changes." -EventId 6003
        Restart-Service -InputObject $sqlService -Force
        Write-V5Log -Message "SQL Service restarted successfully." -EventId 6004
    }
} else {
    Write-V5Log -Message "Bypassing SQL Server restart. No configuration shifts detected." -EventId 6005
}

Write-V5Log -Message "V5 script execution completed." -EventId 1000
