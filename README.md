# SSRS Certificate Auto-Renewal Automation

PowerShell solution to automatically renew **SQL Server Reporting Services (SSRS)** certificates using Windows Certificate Services Lifecycle Notifications.

## Origin
Specialized fork of [Borgquite/CertificateNotificationTasks](https://github.com/Borgquite/CertificateNotificationTasks) for SSRS environments.

- `Update-RenewedSystemCertificates_Original.ps1` = Original unmodified script from the base repository.

## Current Status
**Recommended working versions:**
- **`Update-RenewedSystemCertificates_V5.ps1`** → **Recommended** (Common Name + SAN)
- **`Update-RenewedSystemCertificates_V6.ps1`** → Common Name only

## SQL Server / SSRS Version Reference

| SSRS Version          | SQL Server Version | WMI Namespace Version | Namespace Example                                      | CIM Class Used                     |
|-----------------------|--------------------|-----------------------|--------------------------------------------------------|------------------------------------|
| SSRS 2016             | SQL 2016           | v13                   | `root\Microsoft\SqlServer\ReportServer\RS_SSRS\v13\Admin` | MSReportServer_ConfigurationSetting |
| **SSRS 2017**         | **SQL 2017**       | **v14**               | `root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin` | MSReportServer_ConfigurationSetting |
| SSRS 2019             | SQL 2019           | v15                   | `root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15\Admin` | MSReportServer_ConfigurationSetting |
| SSRS 2022+            | SQL 2022+          | v16                   | `root\Microsoft\SqlServer\ReportServer\RS_SSRS\v16\Admin` | MSReportServer_ConfigurationSetting |

> **Your current environment**: SSRS 2017 (v14) with namespace `root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin`

## Features
- Triggers on certificate **Replace** events for "Internal Web Server" templates
- Fixes **Web Portal showing UNKNOWN** after renewal
- Robust CIM error handling + debug mode
- Duplicate event prevention
- Automatic URL re-reservation and SSL binding updates

## Files

| File                                              | Description                                      | Status                  |
|---------------------------------------------------|--------------------------------------------------|-------------------------|
| `Deploy-CertificateRenewalTasks.ps1`              | Deploys the certificate notification task        | Active                  |
| `Update-RenewedSystemCertificates_V5.ps1`         | **Recommended** – CN + SAN                       | **Working**             |
| `Update-RenewedSystemCertificates_V6.ps1`         | Common Name only                                 | **Working**             |
| `Update-RenewedSystemCertificates_Original.ps1`   | Original script from Borgquite repo              | Reference only          |
| V1–V4                                             | Historical versions                              | Archive                 |

## Deployment

1. Open PowerShell **as Administrator**.
2. Run:
   ```powershell
   .\Deploy-CertificateRenewalTasks.ps1
   ```

## Manual Testing

```powershell
# Recommended - V5 (CN + SAN)
.\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash "YOUR_NEW_THUMBPRINT" -OldCertHash "YOUR_OLD_THUMBPRINT" -DebugMode

# Alternative - V6
.\Update-RenewedSystemCertificates_V6.ps1 -NewCertHash "YOUR_NEW_THUMBPRINT" -OldCertHash "YOUR_OLD_THUMBPRINT" -DebugMode
```

## Troubleshooting
- Run with `-DebugMode` for detailed CIM output.
- Verify your namespace:
  ```powershell
  Get-CimInstance -Namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin" -ClassName MSReportServer_ConfigurationSetting
  ```

## References
- Original Project: [Borgquite/CertificateNotificationTasks](https://github.com/Borgquite/CertificateNotificationTasks)
- Microsoft Article: [Certificate Services Lifecycle Notifications](https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx)
