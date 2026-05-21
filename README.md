# SSRS Certificate Auto-Renewal Automation

This repository is a **fork/specialized version** of [Borgquite/CertificateNotificationTasks](https://github.com/Borgquite/CertificateNotificationTasks) focused on **SQL Server Reporting Services (SSRS)** certificate auto-renewal.

## Origin
- Base scripts come from: https://github.com/Borgquite/CertificateNotificationTasks
- `Update-RenewedSystemCertificates_Original.ps1` = Original unmodified script from the above repository (used by `Deploy-CertificateRenewalTasks.ps1`)

## Current Status
**Working Versions for this environment:**
- **`Update-RenewedSystemCertificates_V5.ps1`** → **Recommended** (Common Name + SAN)
- **`Update-RenewedSystemCertificates_V6.ps1`** → Common Name only

Original version is kept for reference only.

## Features
- Automatic trigger on certificate **Replace** events for "Internal Web Server" template
- Fixes **Web Portal showing UNKNOWN** after renewal
- Robust error handling and debug mode
- Duplicate event prevention
- Re-reserves HTTPS URLs and updates SSL bindings

## Files

| File                                              | Description                                      | Status                  |
|---------------------------------------------------|--------------------------------------------------|-------------------------|
| `Deploy-CertificateRenewalTasks.ps1`              | Deploys the certificate notification task        | Active                  |
| `Update-RenewedSystemCertificates_V5.ps1`         | **Recommended** – CN + SAN support               | **Last Working**        |
| `Update-RenewedSystemCertificates_V6.ps1`         | Common Name only                                 | **Last Working**        |
| `Update-RenewedSystemCertificates_Original.ps1`   | Original script from Borgquite repo              | Reference only          |
| V1–V4                                             | Historical / testing versions                    | Archive                 |

## Deployment

1. Open PowerShell **as Administrator**.
2. Run:
   ```powershell
   .\Deploy-CertificateRenewalTasks.ps1
   ```

## Manual Testing

```powershell
# Recommended - V5 (Common Name + SAN)
.\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash "YOUR_NEW_THUMBPRINT" -OldCertHash "YOUR_OLD_THUMBPRINT" -DebugMode

# Alternative - V6
.\Update-RenewedSystemCertificates_V6.ps1 -NewCertHash "YOUR_NEW_THUMBPRINT" -OldCertHash "YOUR_OLD_THUMBPRINT" -DebugMode
```

## Troubleshooting
- Run with `-DebugMode` for detailed CIM/namespace output.
- Verify SSRS configuration class:
  ```powershell
  Get-CimInstance -Namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin" -ClassName MSReportServer_ConfigurationSetting
  ```

## References
- Original Project: [Borgquite/CertificateNotificationTasks](https://github.com/Borgquite/CertificateNotificationTasks)
- Microsoft Article: [Certificate Services Lifecycle Notifications](https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx)
