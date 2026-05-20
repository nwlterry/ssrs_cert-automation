# --- SQL Server Reporting Services (SQL 2017/2019) ---
if ($OldCertHash -ne '' -or ($NewCertificate.Extensions | Where-Object {
    $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "^Template=Internal Web Server\("
})) {

    # SSRS service check
    $SSRSService = Get-Service -Name 'SQLServerReportingServices' -ErrorAction SilentlyContinue
    if ($null -ne $SSRSService) {

        $SystemLocale = Get-WinSystemLocale

        # Get SSRS v15 (SQL 2019) namespace
        $baseNs = "root\Microsoft\SqlServer\ReportServer"
        $instances = Get-CimInstance -Namespace $baseNs -ClassName __Namespace -ErrorAction SilentlyContinue

        foreach ($instance in $instances) {
            $versionNs = "$baseNs\$($instance.Name)"
            $versions = Get-CimInstance -Namespace $versionNs -ClassName __Namespace -ErrorAction SilentlyContinue

            foreach ($ver in $versions) {

                # Target ONLY v15 (SQL 2019)
                if ($ver.Name -ne "v15") { continue }

                $adminNs = "$versionNs\v15\Admin"
                $config = Get-CimInstance -Namespace $adminNs -ClassName MSReportServer_ConfigurationSetting

                if ($null -eq $config) { continue }

                Write-Output "Processing SSRS instance: $($instance.Name) (v15)"

                $bindings = $config | Invoke-CimMethod -MethodName ListSSLCertificateBindings -Arguments @{Lcid=$SystemLocale.LCID}

                foreach ($app in @('ReportServerWebService','ReportServerWebApp')) {

                    for ($i = 0; $i -lt $bindings.Application.Count; $i++) {

                        if ($bindings.Application[$i] -ne $app) { continue }

                        $currentHash = $bindings.CertificateHash[$i]

                        if ($currentHash -eq $OldCertHash -or $currentHash -eq '') {

                            Write-Output "Updating SSL binding for $app (IP: $($bindings.IPAddress[$i]))..."

                            # Remove old binding
                            $config | Invoke-CimMethod -MethodName RemoveSSLCertificateBindings -Arguments @{
                                Application     = $app
                                CertificateHash = $currentHash
                                IPAddress       = $bindings.IPAddress[$i]
                                Port            = $bindings.Port[$i]
                                Lcid            = $SystemLocale.LCID
                            } | Out-Null

                            # Add new binding
                            $config | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{
                                Application     = $app
                                CertificateHash = $NewCertHash.ToLower()
                                IPAddress       = $bindings.IPAddress[$i]
                                Port            = $bindings.Port[$i]
                                Lcid            = $SystemLocale.LCID
                            } | Out-Null
                        }
                    }
                }

                # Enforce HTTPS
                if ($config.SecureConnectionLevel -eq 0) {
                    Write-Output "Enabling HTTPS requirement for SSRS..."
                    $config | Invoke-CimMethod -MethodName SetSecureConnectionLevel -Arguments @{Level=1} | Out-Null
                }
            }
        }

        # Restart SSRS service
        Write-Output "Restarting SSRS service..."
        Restart-Service -Name 'SQLServerReportingServices' -Force -WarningAction SilentlyContinue
    }
}
