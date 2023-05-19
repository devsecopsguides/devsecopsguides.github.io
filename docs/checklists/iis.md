---
layout: default
title: IIS
parent: Checklists
---

# IIS Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden IIS for DevSecOps


| ID    | Description   | Commands   | 
|:---------------|:---------------------|:---------------------|
| `1` | Disable directory browsing	 | `Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site" -name enabled -value $false` |
| `2` | Remove unneeded HTTP headers | `Remove-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name ."X-Powered-By"` |
| `3` | Set secure HTTP response headers | `Add-WebConfigurationProperty -filter "system.webServer/staticContent" -name "clientCache.cacheControlMode" -value "UseMaxAge"<br>Set-WebConfigurationProperty -filter "system.webServer/staticContent/clientCache" -name "cacheControlMaxAge" -value "365.00:00:00"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-Content-Type-Options" -value "nosniff"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-Frame-Options" -value "SAMEORIGIN"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-XSS-Protection" -value "1; mode=block"` |
| `4` | Enable HTTPS and configure SSL/TLS settings | `New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*" -SslFlags 1<br>Set-ItemProperty -Path IIS:\SslBindings\0.0.0.0!443 -Name "SslFlags" -Value "1"<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/anonymousAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/basicAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/digestAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/windowsAuthentication" -name enabled -value $true<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/windowsAuthentication" -name useKernelMode -value $true`  |
| `5` | Restrict access to files and directories	 | `Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/fileExtensions" -name "." -value @{allowed="$false"}<br>Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/hiddenSegments" -name "." -value @{allowed="$false"}<br>Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/denyUrlSequences" -name "." -value @{add="$false"}` | 
| `6` | Enable logging and configure log settings	 | `Set-WebConfigurationProperty -filter "/system.webServer/httpLogging" -name dontLog -value $false<br>` Set-WebConfigurationProperty -filter "/system.webServer/httpLogging" -name logExtFileFlags -value "Date, Time, ClientIP, UserName, SiteName, ComputerName, ServerIP, Method, UriStem, UriQuery, HttpStatus, Win32Status, BytesSent, BytesRecv, TimeTaken | 