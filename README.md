# SSRS certificate auto-renewal

PowerShell automation to renew SQL Server Reporting Services certificates using Windows Certificate Services lifecycle notifications. Fork of Borgquite/CertificateNotificationTasks specialized for SSRS.

## Layout

```
scripts/Deploy-CertificateRenewalTasks.ps1
scripts/Update-RenewedSystemCertificates_V5.ps1   # recommended (CN + SAN)
scripts/Update-RenewedSystemCertificates_V6.ps1   # CN only
archive/                                          # original + log/encryption variants
assets/                                           # screenshots
logs/
GROUP.md
README.md
```

```powershell
.\scripts\Deploy-CertificateRenewalTasks.ps1
.\scripts\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash '...' -OldCertHash '...' -DebugMode
```

Current environment notes in this repo: SSRS 2017 (WMI `v14`).

---

See [GROUP.md](GROUP.md) for sibling repositories. Catalog: https://github.com/nwlterry/nwlterry
