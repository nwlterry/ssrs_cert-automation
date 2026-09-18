# Deploy-CertificateRenewalTasks.ps1
# Based on: https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

$CertificateNotificationTaskName = "SSRS-SystemCertificateRenewalTask"
$NotificationScriptFile = "Update-RenewedSystemCertificates.ps1"
$ScriptDestinationPath = "$env:SystemDrive\#PowerShell"

# Target Internal Web Server certs for SSRS (add others if needed)
$InternalWebCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "^Template=Internal Web Server\(" }
}

if ($InternalWebCerts) {
    if (-not (Test-Path $ScriptDestinationPath -PathType Container)) {
        New-Item $ScriptDestinationPath -ItemType Directory -Force | Out-Null
    }

    $SourceScript = Join-Path $PSScriptRoot $NotificationScriptFile
    $DestScript = Join-Path $ScriptDestinationPath $NotificationScriptFile

    if (-not (Test-Path $DestScript) -or (Get-FileHash $SourceScript).Hash -ne (Get-FileHash $DestScript).Hash) {
        Write-Output "Deploying/updating notification script..."
        Copy-Item $SourceScript $DestScript -Force
        Unblock-File $DestScript

        if (Get-CertificateNotificationTask | Where-Object { $_.Name -eq $CertificateNotificationTaskName }) {
            Remove-CertificateNotificationTask -Name $CertificateNotificationTaskName
        }

        Write-Output "Deploying certificate notification task '$CertificateNotificationTaskName'..."
        New-CertificateNotificationTask -Type Replace `
            -RunTaskForExistingCertificates `
            -PSScript $DestScript `
            -Name $CertificateNotificationTaskName `
            -Channel System | Out-Null
    }
}