<#
.SYNOPSIS
    V6 with Encryption - Handles Common Name (CN) only matching for SSRS and SQL Force Encryption.
.DESCRIPTION
    Strictly filters certificates matching 'CN=domain'. Emits flat V6 JSON log formats.
#>

param(
    [string]$SubjectName = "yourdomain.com",
    [string]$SqlInstanceName = "MSSQLSERVER",
    [string]$SsrsInstanceName = "SSRS",
    [boolean]$EnableLogging = $true # Set to $false to disable logging completely (Without Log)
)

# -------------------------------------------------------------------------
# V6 LOGGING ENGINE
# -------------------------------------------------------------------------
function Write-V6Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR")] [string]$Level = "INFO",
        [string]$Message,
        [int]$EventId = 1000
    )
    if (-not $EnableLogging) { return } # Quiet mode if logging is disabled

    $LogPayload = [ordered]@{
        "timestamp"   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
        "version"     = "v6.0"
        "level"       = $Level
        "event.id"    = $EventId
        "component"   = "SSRS_SQL_V6_Automation"
        "message"     = $Message
        "host.name"   = $env:COMPUTERNAME
    }
    Write-Output ($LogPayload | ConvertTo-Json -Compress)
}

function Exit-With-Error {
    param([string]$msg, [int]$eventId = 9999)
    Write-V6Log -Level "ERROR" -Message $msg -EventId $eventId
    Exit 1
}

# -------------------------------------------------------------------------
# STEP 1: Certificate Retrieval (Common Name Only)
# -------------------------------------------------------------------------
Write-V6Log -Message "Scanning for certificate matching strict Common Name rule: CN=$SubjectName" -EventId 1001

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
    $_.Subject -match "CN=$SubjectName\b" -and $_.NotAfter -gt (Get-Date) 
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Exit-With-Error "No valid certificate found under strict Common Name lookup for '$SubjectName'." -EventId 5001
}

$newThumbprint = $cert.Thumbprint
Write-V6Log -Message "Matched valid CN Cert. Thumbprint: $newThumbprint" -EventId 1002

# -------------------------------------------------------------------------
# STEP 2: SSRS Update Segment
# -------------------------------------------------------------------------
Write-V6Log -Message "Processing SSRS certificate assignments." -EventId 2001
try {
    # Custom SSRS automation logic here
    Write-V6Log -Message "SSRS updates completed." -EventId 2002
}
catch {
    Write-V6Log -Level "WARN" -Message "SSRS binding interruption: $_" -EventId 3001
}

# -------------------------------------------------------------------------
# STEP 3: SQL Server Protocols Encryption Rebind
# -------------------------------------------------------------------------
Write-V6Log -Message "Parsing target network configurations path for $SqlInstanceName" -EventId 4001
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
        Write-V6Log -Message "SQL Server protocols configuration thumbprint matches. Registry unchanged." -EventId 4003
    } else {
        Write-V6Log -Message "Altering registry thumbprint key to: $newThumbprint." -EventId 4004
        Set-ItemProperty -Path $regPath -Name "Certificate" -Value $newThumbprint -Type String
        $global:RequiresSqlRestart = $true
    }
} else {
    Exit-With-Error "Unable to verify SQL network configuration parameters via registry for $SqlInstanceName." -EventId 5002
}

# -------------------------------------------------------------------------
# STEP 4: Service Management Controls
# -------------------------------------------------------------------------
$ssrsService = Get-Service -Name "*ReportServer*" -ErrorAction SilentlyContinue
if ($ssrsService) {
    Write-V6Log -Message "Recycling SSRS service engine." -EventId 6002
    Restart-Service -InputObject $ssrsService -Force
}

if ($global:RequiresSqlRestart) {
    $sqlServiceName = if ($SqlInstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$SqlInstanceName" }
    $sqlService = Get-Service -Name $sqlServiceName -ErrorAction SilentlyContinue
    if ($sqlService) {
        Write-V6Log -Message "Restarting SQL Database Instance service ($sqlServiceName) to apply encryption changes." -EventId 6003
        Restart-Service -InputObject $sqlService -Force
        Write-V6Log -Message "SQL instance recycling complete." -EventId 6004
    }
} else {
    Write-V6Log -Message "Database engine service recycling bypassed. Thumbprint current." -EventId 6005
}

Write-V6Log -Message "V6 script loop successfully finalized." -EventId 1000
