---
layout: default
title: SBOM
parent: Checklists
---

# SBOM Security Checklist for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to SBOM for DevSecOps




### Generate SBOM for your software

```
cyclonedx-bom -o sbom.xml
```


### Validate the generated SBOM   

```
bom-validator sbom.xml
```

### Integrate SBOM generation in CI/CD pipeline              

```
Add SBOM generation step in CI/CD script
```


### Regularly update the SBOM tools 

```
apt-get update && apt-get upgrade cyclonedx-bom
```

### Review and analyze SBOM for vulnerabilities

```
sbom-analyzer sbom.xml
```

### Ensure SBOM is comprehensive and includes all components

```
Review SBOM and add missing components
```

### Protect SBOM data with proper access controls  

```
Configure access controls for SBOM data 
```


### Monitor and update SBOM for each release      

```
Automate SBOM update for each release
```

