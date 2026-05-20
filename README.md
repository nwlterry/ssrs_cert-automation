# SSRS Certificate Auto-Renewal Automation

PowerShell scripts to automatically update **SQL Server Reporting Services (SSRS)** certificates using Windows Certificate Services Lifecycle Notifications.

## Features
- Triggers on certificate **Replace** events for "Internal Web Server" templates
- Fixes **Web Portal / WebAccess showing UNKNOWN** after renewal
- Robust version detection (SSRS 2016–2022+)
- Comprehensive **CIM error handling** and logging
- Duplicate event prevention
- Automatic URL re-reservation and binding updates

## Files
- `Deploy-CertificateRenewalTasks.ps1` — Deploys the scheduled task
- `Update-RenewedSystemCertificates.ps1` — Main renewal logic (with error handling)

## Deployment
1. Download/clone the repo
2. Run `Deploy-CertificateRenewalTasks.ps1` **as Administrator**
3. The task will auto-trigger on future certificate renewals

## Manual Testing
```powershell
.\Update-RenewedSystemCertificates.ps1 -NewCertHash "YOURNEWCERTTHUMBPRINT" -OldCertHash "OLDCERTTHUMBPRINT"
```

## References
- [Certificate Services Lifecycle Notifications](https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx)

## Changelog
- **Latest**: Full CIM Try/Catch error handling, better namespace detection, URL fixes

Made with ❤️ for SSRS admins.
