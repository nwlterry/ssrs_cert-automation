# SSRS Certificate Auto-Renewal Automation

PowerShell solution to automatically renew SSRS certificates using Windows Certificate Services Lifecycle Notifications.

## Important Note
- The generic `Update-RenewedSystemCertificates.ps1` (hardcoded namespace version) **does not work** on this server due to namespace detection issues.
- **Last working versions**: **V5** and **V6**

## Recommended Version
**V5** → Uses **Common Name + SAN** (best for most certificates)

## Files
| File | Description | Status |
|------|-------------|--------|
| `Update-RenewedSystemCertificates_V5.ps1` | Common Name + SAN | Stable / Working |
| `Update-RenewedSystemCertificates_V6.ps1` | Common Name only | Stable / Working |
| `Deploy-CertificateRenewalTasks.ps1` | Deployment script | Updated |

## Version History

| Version | DNS Extraction | Status | Recommendation |
|---------|----------------|--------|----------------|
| V5      | CN + SAN       | **Working** | **Recommended** |
| V6      | CN only        | **Working** | Use if only CN is needed |
| Others  | Various        | Not working | Avoid |

## Deployment
1. Run PowerShell **as Administrator**
2. Execute:
   ```powershell
   .\Deploy-CertificateRenewalTasks.ps1
   ```
3. The task will trigger automatically on certificate replacement.

## Manual Testing
```powershell
# Test V5 or V6 (recommended)
.\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash "NEW_THUMBPRINT" -OldCertHash "OLD_THUMBPRINT" -DebugMode

# Or directly
.\Update-RenewedSystemCertificates_V5.ps1 -NewCertHash "..." -OldCertHash "..."
```

## Troubleshooting
- Run with `-DebugMode` to see detailed output.
- Check SSRS namespace with:
  ```powershell
  Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer\RS_SSRS\V14\Admin -ClassName MSReportServer_ConfigurationSetting
  ```

## References
- [Certificate Services Lifecycle Notifications](https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx)
