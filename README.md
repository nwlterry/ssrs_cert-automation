# SSRS Certificate Auto-Renewal Automation

PowerShell scripts to automatically update **SQL Server Reporting Services (SSRS)** certificates using Windows Certificate Services Lifecycle Notifications.

## Features
- Triggers on certificate **Replace** events for "Internal Web Server" templates
- Fixes **Web Portal / WebAccess showing UNKNOWN** after renewal
- Supports Common Name + SAN extraction
- Robust CIM error handling and debug logging
- Duplicate event prevention
- Automatic URL re-reservation and SSL binding updates

## Files
- **Deploy-CertificateRenewalTasks.ps1** — Deploys the scheduled task
- **Update-RenewedSystemCertificates.ps1** — Current main script (hardcoded for your environment: `RS_SSRS\V14\Admin`)
- Versioned scripts (V1–V6) for reference

## Version History

| Version | Description                              | Status          | Notes |
|---------|------------------------------------------|-----------------|-------|
| **V6**  | Common Name only                         | **Last Working** | Simplified DNS extraction |
| **V5**  | Common Name + SAN (full)                 | **Last Working** | Recommended for most certs |
| V4      | Improved namespace detection             | Historical      | - |
| V1–V3   | Early versions                           | Historical      | - |
| Latest  | Hardcoded to `RS_SSRS\V14\Admin` + debug| In Use          | Tailored to your server |

## Deployment
1. Clone or download the repository
2. Run `Deploy-CertificateRenewalTasks.ps1` **as Administrator**
3. The task will automatically run on future certificate renewals

## Manual Testing
```powershell
# Test with full DNS (SAN + CN)
.\Update-RenewedSystemCertificates.ps1 -NewCertHash "YOUR_NEW_THUMBPRINT" -OldCertHash "YOUR_OLD_THUMBPRINT" -DebugMode

# Or use one of the stable versions directly
.\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash "..." -OldCertHash "..."
