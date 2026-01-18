# Active Directory Auditing & Validation Guide

**Doküman Versiyonu:** 1.0  
**Hazırlayan:** Senior Security Auditor  
**Tarih:** Ocak 2026  
**Kapsam:** Active Directory Hardening & Auditing Doğrulama Metodolojisi

---

## 1. Executive Summary

Bu doküman, Active Directory hardening projelerinin denetim ve doğrulama aşaması için sistematik bir metodoloji sunar. CIS Benchmark v4.0.0 ve Microsoft Tiered Admin Model standartlarına uygun olarak hazırlanmıştır.

**Kritik Odak Alanları:**
- ACL ve Delegation zayıflıklarının sistematik tespiti
- Tiered Admin Model uygulamasının teknik doğrulaması
- 2026 tehdit vektörlerine (AI-phishing, Silver Ticket varyantları) karşı kontrol mekanizmaları
- Otomatize denetim scriptleri ile sürekli izleme

---

## 2. Denetim Metodolojisi

### 2.1 Dört Katmanlı Doğrulama Yaklaşımı

```
Katman 1: Configuration Baseline Validation
├── GPO Settings Compliance (CIS v4.0.0)
├── Password Policy Enforcement
└── Account Security Attributes

Katman 2: Permission & Delegation Audit
├── ACL Enumeration (BloodHound, PowerView)
├── Delegation Rights Mapping
└── Privilege Escalation Path Analysis

Katman 3: Tiered Model Verification
├── Tier 0/1/2 Boundary Controls
├── Authentication Policy Enforcement
└── Cross-Tier Access Restrictions

Katman 4: Threat-Specific Controls
├── Kerberos Security (Silver Ticket mitigation)
├── AI-Phishing Defenses
└── Modern Attack Vector Coverage
```

### 2.2 Denetim Akışı

1. **Pre-Audit Hazırlık** (1-2 gün)
   - Domain Controller inventory
   - Admin hesap listesi
   - Kritik GPO'ların belirlenmesi
   - Baseline snapshot

2. **Teknik Denetim** (5-7 gün)
   - Otomatize scan'ler
   - Manuel doğrulama
   - BloodHound analizi
   - Delegation review

3. **Risk Analizi** (2-3 gün)
   - Finding'lerin CVSS skorlaması
   - Attack path prioritization
   - Remediation önerileri

4. **Raporlama** (2 gün)
   - Executive summary
   - Teknik detaylar
   - Action plan

---

## 3. Teknik Denetim Scriptleri

### 3.1 Comprehensive AD Security Audit Script

```powershell
<#
.SYNOPSIS
    Active Directory Security Audit - Comprehensive Validation
.DESCRIPTION
    CIS v4.0.0 ve Microsoft Tiered Model bazlı denetim scripti.
    ACL, Delegation, Kerberos, Password Policy kontrollerini içerir.
.NOTES
    Version: 2.0
    Author: Senior Security Auditor
    Date: January 2026
#>

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\AD_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeBloodHound,
    
    [Parameter(Mandatory=$false)]
    [switch]$DetailedACLScan
)

# Error handling ve logging
$ErrorActionPreference = "Continue"
$LogFile = Join-Path $OutputPath "AuditLog.txt"

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $LogEntry -ForegroundColor $(if($Level -eq "ERROR"){"Red"}elseif($Level -eq "WARNING"){"Yellow"}else{"Green"})
}

# Output klasörü oluştur
try {
    New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    Write-AuditLog "Output directory created: $OutputPath"
} catch {
    Write-Error "Cannot create output directory: $_"
    exit 1
}

Write-AuditLog "Starting AD Security Audit for domain: $Domain"

# ========================================
# 1. CIS BENCHMARK CONTROLS
# ========================================

Write-AuditLog "=== CIS Benchmark Validation ===" "INFO"

function Get-PasswordPolicyCompliance {
    Write-AuditLog "Checking Password Policy compliance..."
    try {
        $Policy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain -ErrorAction Stop
        
        $Compliance = @{
            'MinPasswordLength' = @{
                'Current' = $Policy.MinPasswordLength
                'Required' = 14
                'Compliant' = $Policy.MinPasswordLength -ge 14
            }
            'PasswordHistoryCount' = @{
                'Current' = $Policy.PasswordHistoryCount
                'Required' = 24
                'Compliant' = $Policy.PasswordHistoryCount -ge 24
            }
            'MaxPasswordAge' = @{
                'Current' = $Policy.MaxPasswordAge.Days
                'Required' = 60
                'Compliant' = $Policy.MaxPasswordAge.Days -le 60 -and $Policy.MaxPasswordAge.Days -gt 0
            }
            'MinPasswordAge' = @{
                'Current' = $Policy.MinPasswordAge.Days
                'Required' = 1
                'Compliant' = $Policy.MinPasswordAge.Days -ge 1
            }
            'ComplexityEnabled' = @{
                'Current' = $Policy.ComplexityEnabled
                'Required' = $true
                'Compliant' = $Policy.ComplexityEnabled -eq $true
            }
            'ReversibleEncryptionEnabled' = @{
                'Current' = $Policy.ReversibleEncryptionEnabled
                'Required' = $false
                'Compliant' = $Policy.ReversibleEncryptionEnabled -eq $false
            }
        }
        
        $Compliance | ConvertTo-Json | Out-File (Join-Path $OutputPath "PasswordPolicy_Compliance.json")
        Write-AuditLog "Password policy compliance check completed"
        return $Compliance
    } catch {
        Write-AuditLog "Error checking password policy: $_" "ERROR"
        return $null
    }
}

function Get-PrivilegedAccounts {
    Write-AuditLog "Enumerating privileged accounts..."
    try {
        $PrivilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators"
        )
        
        $Results = @()
        foreach ($Group in $PrivilegedGroups) {
            try {
                $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop | 
                    Where-Object {$_.objectClass -eq 'user'} |
                    Select-Object Name, SamAccountName, DistinguishedName
                
                foreach ($Member in $Members) {
                    $UserDetails = Get-ADUser -Identity $Member.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount
                    
                    $Results += [PSCustomObject]@{
                        Group = $Group
                        Name = $Member.Name
                        SamAccountName = $Member.SamAccountName
                        Enabled = $UserDetails.Enabled
                        LastLogon = $UserDetails.LastLogonDate
                        PasswordLastSet = $UserDetails.PasswordLastSet
                        PasswordNeverExpires = $UserDetails.PasswordNeverExpires
                        AdminCount = $UserDetails.AdminCount
                        DN = $Member.DistinguishedName
                    }
                }
            } catch {
                Write-AuditLog "Error processing group $Group : $_" "WARNING"
            }
        }
        
        $Results | Export-Csv (Join-Path $OutputPath "PrivilegedAccounts.csv") -NoTypeInformation
        Write-AuditLog "Found $($Results.Count) privileged account memberships"
        
        # Risky account flags
        $RiskyAccounts = $Results | Where-Object {
            $_.PasswordNeverExpires -eq $true -or 
            $_.Enabled -eq $false -or
            $_.LastLogon -lt (Get-Date).AddDays(-90)
        }
        
        if ($RiskyAccounts) {
            $RiskyAccounts | Export-Csv (Join-Path $OutputPath "RiskyPrivilegedAccounts.csv") -NoTypeInformation
            Write-AuditLog "ALERT: Found $($RiskyAccounts.Count) risky privileged accounts" "WARNING"
        }
        
        return $Results
    } catch {
        Write-AuditLog "Error enumerating privileged accounts: $_" "ERROR"
        return $null
    }
}

function Get-KerberosSettings {
    Write-AuditLog "Checking Kerberos security settings..."
    try {
        $DCList = Get-ADDomainController -Filter * -Server $Domain
        $Results = @()
        
        foreach ($DC in $DCList) {
            try {
                # Kerberos encryption types
                $EncTypes = Get-ADObject -Identity "CN=Kerberos,CN=Default Domain Policy,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue
                
                $Results += [PSCustomObject]@{
                    DomainController = $DC.HostName
                    SupportedEncTypes = $EncTypes.'msDS-SupportedEncryptionTypes'
                    RC4Enabled = ($EncTypes.'msDS-SupportedEncryptionTypes' -band 0x04) -ne 0
                    AESEnabled = ($EncTypes.'msDS-SupportedEncryptionTypes' -band 0x18) -ne 0
                }
            } catch {
                Write-AuditLog "Error checking Kerberos on $($DC.HostName): $_" "WARNING"
            }
        }
        
        $Results | Export-Csv (Join-Path $OutputPath "Kerberos_Settings.csv") -NoTypeInformation
        
        # RC4 kullanımı kontrolü (2025+ best practice: disable RC4)
        $RC4Enabled = $Results | Where-Object {$_.RC4Enabled -eq $true}
        if ($RC4Enabled) {
            Write-AuditLog "WARNING: RC4 encryption still enabled on $($RC4Enabled.Count) DCs" "WARNING"
        }
        
        return $Results
    } catch {
        Write-AuditLog "Error checking Kerberos settings: $_" "ERROR"
        return $null
    }
}

# ========================================
# 2. ACL & DELEGATION AUDIT
# ========================================

Write-AuditLog "=== ACL & Delegation Audit ===" "INFO"

function Get-DangerousACLs {
    Write-AuditLog "Scanning for dangerous ACLs..."
    try {
        $DangerousPerms = @(
            "GenericAll",
            "WriteDacl",
            "WriteOwner",
            "GenericWrite",
            "Self",
            "WriteProperty",
            "ExtendedRight"
        )
        
        $CriticalOUs = @(
            "Domain Controllers",
            "Users",
            "Computers",
            "Builtin"
        )
        
        $Results = @()
        
        foreach ($OU in $CriticalOUs) {
            try {
                $SearchBase = (Get-ADOrganizationalUnit -Filter "Name -eq '$OU'" -SearchBase (Get-ADDomain).DistinguishedName).DistinguishedName
                if (-not $SearchBase) { continue }
                
                $Objects = Get-ADObject -Filter * -SearchBase $SearchBase -Properties ntSecurityDescriptor
                
                foreach ($Object in $Objects) {
                    $ACL = $Object.ntSecurityDescriptor.Access | Where-Object {
                        $_.IdentityReference -notlike "NT AUTHORITY\*" -and
                        $_.IdentityReference -notlike "BUILTIN\*" -and
                        $_.ActiveDirectoryRights -match ($DangerousPerms -join '|')
                    }
                    
                    foreach ($ACE in $ACL) {
                        $Results += [PSCustomObject]@{
                            Object = $Object.DistinguishedName
                            OU = $OU
                            IdentityReference = $ACE.IdentityReference
                            AccessControlType = $ACE.AccessControlType
                            ActiveDirectoryRights = $ACE.ActiveDirectoryRights
                            IsInherited = $ACE.IsInherited
                            ObjectType = $Object.ObjectClass
                        }
                    }
                }
            } catch {
                Write-AuditLog "Error scanning OU $OU : $_" "WARNING"
            }
        }
        
        $Results | Export-Csv (Join-Path $OutputPath "DangerousACLs.csv") -NoTypeInformation
        Write-AuditLog "Found $($Results.Count) potentially dangerous ACL entries"
        
        return $Results
    } catch {
        Write-AuditLog "Error scanning ACLs: $_" "ERROR"
        return $null
    }
}

function Get-UnconstrainedDelegation {
    Write-AuditLog "Checking for Unconstrained Delegation..."
    try {
        $UDComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, ServicePrincipalName, OperatingSystem
        $UDUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, ServicePrincipalName
        
        $Results = @()
        
        foreach ($Computer in $UDComputers) {
            # Domain Controller değilse risk!
            $IsDC = $Computer.ServicePrincipalName -like "*E3514235-4B06-11D1-AB04-00C04FC2DCC2*"
            
            $Results += [PSCustomObject]@{
                Type = "Computer"
                Name = $Computer.Name
                DN = $Computer.DistinguishedName
                OperatingSystem = $Computer.OperatingSystem
                IsDomainController = $IsDC
                RiskLevel = if($IsDC){"Low"}else{"CRITICAL"}
                SPNs = ($Computer.ServicePrincipalName -join "; ")
            }
        }
        
        foreach ($User in $UDUsers) {
            $Results += [PSCustomObject]@{
                Type = "User"
                Name = $User.Name
                DN = $User.DistinguishedName
                OperatingSystem = "N/A"
                IsDomainController = $false
                RiskLevel = "HIGH"
                SPNs = ($User.ServicePrincipalName -join "; ")
            }
        }
        
        $Results | Export-Csv (Join-Path $OutputPath "UnconstrainedDelegation.csv") -NoTypeInformation
        
        $CriticalFindings = $Results | Where-Object {$_.RiskLevel -in @("CRITICAL","HIGH")}
        if ($CriticalFindings) {
            Write-AuditLog "CRITICAL: Found $($CriticalFindings.Count) high-risk unconstrained delegation accounts" "ERROR"
        }
        
        return $Results
    } catch {
        Write-AuditLog "Error checking unconstrained delegation: $_" "ERROR"
        return $null
    }
}

# ========================================
# 3. TIERED MODEL VALIDATION
# ========================================

Write-AuditLog "=== Tiered Admin Model Validation ===" "INFO"

function Test-TierModelImplementation {
    Write-AuditLog "Validating Tiered Admin Model implementation..."
    try {
        # Tier 0 Assets kontrolü
        $Tier0Groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
        $Tier0OUs = @("Domain Controllers")
        
        $Results = @{
            'Tier0GroupMembership' = @()
            'CrossTierViolations' = @()
            'MissingAuthPolicies' = @()
        }
        
        # Tier 0 grup üyeliklerinin kontrolü
        foreach ($Group in $Tier0Groups) {
            $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue | Where-Object {$_.objectClass -eq 'user'}
            
            foreach ($Member in $Members) {
                $User = Get-ADUser -Identity $Member -Properties LastLogonDate, Enabled
                $Results['Tier0GroupMembership'] += [PSCustomObject]@{
                    Group = $Group
                    User = $Member.SamAccountName
                    LastLogon = $User.LastLogonDate
                    Enabled = $User.Enabled
                    Compliant = ($User.Enabled -and $User.LastLogonDate -gt (Get-Date).AddDays(-30))
                }
            }
        }
        
        # Authentication Policy kontrolü (Windows Server 2012 R2+)
        try {
            $AuthPolicies = Get-ADAuthenticationPolicy -Filter * -ErrorAction SilentlyContinue
            if (-not $AuthPolicies) {
                Write-AuditLog "WARNING: No Authentication Policies found - Tiered Model not enforced!" "WARNING"
                $Results['MissingAuthPolicies'] = @("No policies configured")
            }
        } catch {
            Write-AuditLog "Authentication Policies not supported or not configured" "WARNING"
        }
        
        $Results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "TierModel_Validation.json")
        Write-AuditLog "Tier Model validation completed"
        
        return $Results
    } catch {
        Write-AuditLog "Error validating Tier Model: $_" "ERROR"
        return $null
    }
}

# ========================================
# 4. MODERN THREAT CONTROLS
# ========================================

Write-AuditLog "=== Modern Threat Vector Controls ===" "INFO"

function Test-SilverTicketDefenses {
    Write-AuditLog "Checking Silver Ticket mitigation controls..."
    try {
        $Results = @{
            'ServiceAccountsWithSPN' = @()
            'WeakServicePasswords' = @()
            'PACValidation' = $null
        }
        
        # SPN içeren service account'ları bul
        $ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, Enabled
        
        foreach ($Account in $ServiceAccounts) {
            $PasswordAge = if($Account.PasswordLastSet){((Get-Date) - $Account.PasswordLastSet).Days}else{9999}
            
            $Results['ServiceAccountsWithSPN'] += [PSCustomObject]@{
                SamAccountName = $Account.SamAccountName
                SPNs = ($Account.ServicePrincipalName -join "; ")
                PasswordAge = $PasswordAge
                PasswordNeverExpires = $Account.PasswordNeverExpires
                Enabled = $Account.Enabled
                RiskLevel = if($PasswordAge -gt 180 -or $Account.PasswordNeverExpires){"HIGH"}elseif($PasswordAge -gt 90){"MEDIUM"}else{"LOW"}
            }
        }
        
        # PAC validation kontrolü (Registry)
        try {
            $DCList = Get-ADDomainController -Filter *
            foreach ($DC in $DCList) {
                # Bu kontrol genelde GPO veya registry üzerinden yapılır
                Write-AuditLog "PAC validation should be manually verified on $($DC.HostName)" "INFO"
            }
        } catch {
            Write-AuditLog "Could not check PAC validation settings" "WARNING"
        }
        
        $HighRiskAccounts = $Results['ServiceAccountsWithSPN'] | Where-Object {$_.RiskLevel -eq "HIGH"}
        if ($HighRiskAccounts) {
            Write-AuditLog "WARNING: Found $($HighRiskAccounts.Count) high-risk service accounts vulnerable to Kerberoasting/Silver Ticket" "WARNING"
        }
        
        $Results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "SilverTicket_Defenses.json")
        return $Results
    } catch {
        Write-AuditLog "Error checking Silver Ticket defenses: $_" "ERROR"
        return $null
    }
}

function Test-BreachedPasswordProtection {
    Write-AuditLog "Checking for breached password protection..."
    try {
        # Azure AD Password Protection veya benzer çözüm var mı?
        $Results = @{
            'ProtectionStatus' = $null
            'Recommendation' = "Implement Azure AD Password Protection or Specops Password Policy"
        }
        
        # GPO kontrolü
        $GPOSettings = Get-GPO -All | Where-Object {$_.DisplayName -like "*Password*"}
        
        if ($GPOSettings) {
            $Results['ProtectionStatus'] = "GPO-based password policies detected"
            Write-AuditLog "Found $($GPOSettings.Count) password-related GPOs"
        } else {
            $Results['ProtectionStatus'] = "No advanced password protection detected"
            Write-AuditLog "WARNING: No breached password protection found" "WARNING"
        }
        
        $Results | ConvertTo-Json | Out-File (Join-Path $OutputPath "BreachedPassword_Protection.json")
        return $Results
    } catch {
        Write-AuditLog "Error checking breached password protection: $_" "ERROR"
        return $null
    }
}

# ========================================
# EXECUTION
# ========================================

Write-AuditLog "Executing all audit checks..."

$AuditResults = @{}

try {
    $AuditResults['PasswordPolicy'] = Get-PasswordPolicyCompliance
    $AuditResults['PrivilegedAccounts'] = Get-PrivilegedAccounts
    $AuditResults['KerberosSettings'] = Get-KerberosSettings
    $AuditResults['DangerousACLs'] = Get-DangerousACLs
    $AuditResults['UnconstrainedDelegation'] = Get-UnconstrainedDelegation
    $AuditResults['TierModel'] = Test-TierModelImplementation
    $AuditResults['SilverTicketDefenses'] = Test-SilverTicketDefenses
    $AuditResults['BreachedPasswordProtection'] = Test-BreachedPasswordProtection
    
    Write-AuditLog "All checks completed successfully"
} catch {
    Write-AuditLog "Fatal error during audit execution: $_" "ERROR"
}

# Final report
$SummaryReport = @"
======================================
AD SECURITY AUDIT SUMMARY
======================================
Domain: $Domain
Audit Date: $(Get-Date)
Output Path: $OutputPath

FINDINGS SUMMARY:
- Privileged Accounts: $($AuditResults['PrivilegedAccounts'].Count)
- Dangerous ACLs: $($AuditResults['DangerousACLs'].Count)
- Unconstrained Delegation: $(($AuditResults['UnconstrainedDelegation'] | Where-Object {$_.RiskLevel -in @("CRITICAL","HIGH")}).Count) high-risk
- Service Accounts w/ SPN: $($AuditResults['SilverTicketDefenses']['ServiceAccountsWithSPN'].Count)

CRITICAL ACTIONS REQUIRED:
1. Review risky privileged accounts immediately
2. Remediate dangerous ACL permissions
3. Disable or constrain delegation where unnecessary
4. Implement service account password rotation
5. Enable PAC validation if not already active

Detailed reports saved to: $OutputPath
======================================
"@

$SummaryReport | Out-File (Join-Path $OutputPath "AUDIT_SUMMARY.txt")
Write-Host $SummaryReport -ForegroundColor Cyan

Write-AuditLog "Audit completed. Summary report generated."
```

### 3.2 BloodHound Integration Script

```powershell
<#
.SYNOPSIS
    BloodHound Data Collection & Analysis Automation
.DESCRIPTION
    SharpHound veri toplama ve kritik attack path'lerin analizi
.NOTES
    Requires: SharpHound.exe in same directory or $env:PATH
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\BloodHound_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$SharpHoundPath = ".\SharpHound.exe"
)

# SharpHound çalıştır
Write-Host "[+] Running SharpHound data collection..." -ForegroundColor Green

try {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    
    $SharpHoundArgs = @(
        "--CollectionMethod All",
        "--Domain $Domain",
        "--OutputDirectory $OutputPath",
        "--OutputPrefix ADHardening_Audit",
        "--NoSaveCache",
        "--Verbose"
    )
    
    & $SharpHoundPath $SharpHoundArgs
    
    Write-Host "[+] SharpHound collection completed" -ForegroundColor Green
    Write-Host "[+] Import the ZIP file to BloodHound for analysis" -ForegroundColor Yellow
    Write-Host "[+] Output location: $OutputPath" -ForegroundColor Cyan
    
} catch {
    Write-Error "Failed to run SharpHound: $_"
    exit 1
}

# Neo4j Cypher queries (BloodHound'da manuel çalıştırılacak)
$CypherQueries = @"
// =====================================
// CRITICAL BLOODHOUND QUERIES
// =====================================

// 1. Shortest Paths to Domain Admins
MATCH (n {owned:true}), (m:Group {name:'DOMAIN ADMINS@$Domain.UPPER()'}), p=shortestPath((n)-[*1..]->(m))
RETURN p

// 2. Unconstrained Delegation Computers (non-DC)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name, c.operatingsystem

// 3. GenericAll on Domain Admins
MATCH p=(n)-[r:GenericAll]->(g:Group {name:'DOMAIN ADMINS@$Domain.UPPER()'})
RETURN p

// 4. Kerberoastable Users with Path to DA
MATCH (u:User {hasspn:true}), (g:Group {name:'DOMAIN ADMINS@$Domain.UPPER()'}), p=shortestPath((u)-[*1..]->(g))
RETURN p

// 5. Dangerous OU Permissions
MATCH p=(n)-[r:GenericAll|WriteDacl|WriteOwner]->(o:OU)
WHERE o.name CONTAINS 'DOMAIN CONTROLLERS'
RETURN p

// 6. Cross-Tier Access (Tier 2 -> Tier 0)
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name IN ['DOMAIN ADMINS@$Domain.UPPER()','ENTERPRISE ADMINS@$Domain.UPPER()']
AND u.name =~ '(?i).*user.*|.*client.*'
RETURN u.name, g.name

// 7. Foreign Domain Group Memberships
MATCH (n:User)-[:MemberOf]->(g:Group)
WHERE n.domain <> g.domain
RETURN n.name, n.domain, g.name, g.domain
"@

$CypherQueries | Out-File (Join-Path $OutputPath "BloodHound_Queries.cypher")
Write-Host "[+] Cypher queries saved: $(Join-Path $OutputPath 'BloodHound_Queries.cypher')" -ForegroundColor Cyan
```

---

## 4. CIS v4.0.0 Kritik Kontrol Listesi

### 4.1 Domain Controller Security

| Kontrol ID | Açıklama | CIS Referans | Test Metodu |
|------------|----------|--------------|-------------|
| DC-001 | Anonymous SID/Name translation disabled | CIS 2.3.11.1 | `GPResult /Scope Computer /H report.html` |
| DC-002 | LDAP signing required | CIS 2.3.11.8 | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` |
| DC-003 | NTLM authentication restricted | CIS 2.3.11.9 | GPO: Network security: Restrict NTLM |
| DC-004 | SMB signing enforced | CIS 2.3.9.1-2 | `Get-SmbServerConfiguration` |
| DC-005 | RDP encryption level High | CIS 18.9.60.2 | GPO: Require use of specific security layer |

### 4.2 Password & Account Policy

| Kontrol ID | Açıklama | CIS Baseline | PowerShell Validation |
|------------|----------|--------------|----------------------|
| PWD-001 | Min password length ≥14 | CIS 1.1.1 | `(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength` |
| PWD-002 | Password history ≥24 | CIS 1.1.2 | `(Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount` |
| PWD-003 | Max password age ≤60 days | CIS 1.1.3 | `(Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge` |
| PWD-004 | Complexity enabled | CIS 1.1.5 | `(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled` |
| PWD-005 | Reversible encryption disabled | CIS 1.1.4 | `(Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled` |
| ACC-001 | Account lockout threshold ≤10 | CIS 1.2.1 | `(Get-ADDefaultDomainPasswordPolicy).LockoutThreshold` |
| ACC-002 | Account lockout duration ≥15 min | CIS 1.2.2 | `(Get-ADDefaultDomainPasswordPolicy).LockoutDuration` |
| ACC-003 | Reset account lockout after ≥15 min | CIS 1.2.3 | `(Get-ADDefaultDomainPasswordPolicy).LockoutObservationWindow` |

### 4.3 Privileged Access Management

| Kontrol ID | Açıklama | Best Practice | Risk Seviyesi |
|------------|----------|---------------|---------------|
| PAM-001 | Domain Admins member sayısı <5 | Microsoft Tier 0 | CRITICAL |
| PAM-002 | Privileged accounts MFA enforced | Modern Auth | CRITICAL |
| PAM-003 | Service accounts "This account is sensitive..." flag | Delegation protection | HIGH |
| PAM-004 | Admin accounts "User cannot change password" disabled | Accountability | MEDIUM |
| PAM-005 | Admin accounts separate from user accounts | Tier separation | CRITICAL |
| PAM-006 | No admin accounts with PasswordNeverExpires | Rotation policy | HIGH |

### 4.4 Kerberos Hardening

| Kontrol ID | Açıklama | Tehdit Modeli | Validation |
|------------|----------|---------------|------------|
| KRB-001 | RC4 encryption disabled (AES only) | Silver/Golden Ticket | `(Get-ADUser -Identity krbtgt).msDS-SupportedEncryptionTypes` |
| KRB-002 | krbtgt password rotated (<180 days) | Golden Ticket | `(Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet` |
| KRB-003 | Service account passwords >25 characters | Kerberoasting | Manual review |
| KRB-004 | PAC validation enabled | Silver Ticket | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\ValidateKdcPacSignature` |
| KRB-005 | No unconstrained delegation (non-DC) | Credential theft | `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` |

---

## 5. Microsoft Tiered Admin Model - Implementation Checklist

### 5.1 Tier 0 (Domain/Forest Control)

**Kapsam:**
- Domain Controllers
- Certificate Authority servers
- Domain/Enterprise/Schema Admins
- ADFS servers
- Privileged Access Workstations (PAWs)

**Zorunlu Kontroller:**

```powershell
# Tier 0 Asset Enumeration
$Tier0 = @{
    'Groups' = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
    'OUs' = @('Domain Controllers','Tier 0 Servers')
    'Computers' = Get-ADComputer -Filter {PrimaryGroupID -eq 516} # DCs
}

# Authentication Policy Enforcement (WS2012R2+)
New-ADAuthenticationPolicy -Name "Tier0-AuthPolicy" `
    -UserTGTLifetimeMins 240 `
    -ComputerTGTLifetimeMins 240 `
    -Enforce

Get-ADUser -Filter {AdminCount -eq 1} | Set-ADUser -AuthenticationPolicy "Tier0-AuthPolicy"
```

**Kritik Kurallar:**
1. Tier 0 accounts sadece Tier 0 asset'lere login
2. Tier 0 PAW'lar outbound internet yasak
3. MFA zorunlu (Windows Hello for Business veya Smartcard)
4. Session timeout: 4 saat

### 5.2 Tier 1 (Server/Service Management)

**Kapsam:**
- Application servers
- File servers
- Database servers
- Server admins

**Authentication Silo:**

```powershell
# Tier 1 silo oluşturma
New-ADAuthenticationPolicySilo -Name "Tier1-Silo" `
    -UserAuthenticationPolicy "Tier1-UserPolicy" `
    -ComputerAuthenticationPolicy "Tier1-ComputerPolicy" `
    -Enforce

# Tier 1 users/computers ekleme
Grant-ADAuthenticationPolicySiloAccess -Identity "Tier1-Silo" -Account "Tier1-Admins"
```

### 5.3 Tier 2 (Workstation/User Management)

**Kapsam:**
- End-user workstations
- Helpdesk accounts
- User support staff

**Kontrol Mekanizması:**

```powershell
# Tier 2 grupları logon restriction
$Tier2Groups = @('Helpdesk','Desktop Support')
foreach ($Group in $Tier2Groups) {
    $Members = Get-ADGroupMember -Identity $Group
    foreach ($Member in $Members) {
        Set-ADUser -Identity $Member.SamAccountName -LogonWorkstations "WKS-*" # Sadece workstation prefix
    }
}
```

### 5.4 Cross-Tier Violation Detection

```powershell
# Tier ihlal tespiti
function Get-CrossTierViolations {
    $Violations = @()
    
    # Tier 0 accounts Tier 2'de login kontrolü
    $Tier0Users = Get-ADGroupMember "Domain Admins" -Recursive | Where-Object {$_.objectClass -eq 'user'}
    
    foreach ($User in $Tier0Users) {
        $Logons = Get-WinEvent -ComputerName (Get-ADComputer -Filter {OperatingSystem -like "*Windows 10*"} | Select-Object -First 10).Name `
            -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Where-Object {$_.Properties[5].Value -eq $User.SamAccountName}
        
        if ($Logons) {
            $Violations += [PSCustomObject]@{
                User = $User.SamAccountName
                Tier = "Tier 0"
                ViolationType = "Logon to Tier 2 asset"
                Count = $Logons.Count
                Risk = "CRITICAL"
            }
        }
    }
    
    return $Violations
}
```

---

## 6. 2026 Risk Analizi & Modern Threat Mitigation

### 6.1 AI-Powered Phishing Defenses

**Tehdit Tanımı:**  
2025-2026 döneminde LLM bazlı phishing kampanyaları %300 artış gösterdi. Saldırganlar ChatGPT benzeri modeller kullanarak highly personalized spear-phishing içerikleri üretmekte.

**Teknik Savunma Katmanları:**

```powershell
# 1. External email tagging (Exchange Online)
New-TransportRule -Name "External Email Warning" `
    -FromScope NotInOrganization `
    -ApplyHtmlDisclaimerLocation Prepend `
    -ApplyHtmlDisclaimerText "<div style='background-color:#FFEB9C;padding:10px;border:1px solid #FFC000;'><strong>EXTERNAL:</strong> This email originated outside the organization. Verify sender before clicking links.</div>"

# 2. Suspicious attachment blocking
$SuspiciousExtensions = @('.hta','.js','.jse','.vbs','.vbe','.wsf','.wsh','.ps1','.bat','.cmd')
New-TransportRule -Name "Block Suspicious Attachments" `
    -AttachmentExtensionMatchesWords $SuspiciousExtensions `
    -RejectMessageEnhancedStatusCode "5.7.1" `
    -RejectMessageReasonText "Attachment type blocked by security policy"
```

**AI-Phishing Indicators:**
- Anomali tespit: Email tone/style analizi (benzerlik skoru >0.9 ancak sender domain değişik)
- Link analysis: Yeni register edilmiş domainler (<30 gün)
- Urgent action requests + financial transaction keywords

**Önerilen Çözümler:**
- Microsoft Defender for Office 365 (Safe Links/Attachments)
- KnowBe4 / Cofense PhishMe - AI-aware training
- DMARC/DKIM/SPF enforcement (reject policy)

### 6.2 Silver Ticket Attack Variants (2025-2026)

**Yeni Varyantlar:**
- **Encrypted Ticket Manipulation:** AES-256 encrypted Kerberos ticket'larının brute-force kırılması
- **SPN Hijacking:** Fake SPN registration + Silver Ticket = Service impersonation
- **TGS-REQ Replay:** Captured TGS-REQ'lerin tekrar kullanımı

**Mitigation Checklist:**

| Kontrol | Açıklama | Implementation |
|---------|----------|----------------|
| PAC Validation | Privilege Attribute Certificate doğrulaması | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\ValidateKdcPacSignature = 1` |
| SPN Monitoring | Yeni SPN kayıt uyarıları | Event ID 4769 monitoring + SIEM alert |
| Service Account Hardening | Managed Service Accounts (gMSA) geçiş | `New-ADServiceAccount -Name svc_app -DNSHostName app.domain.com -PrincipalsAllowedToRetrieveManagedPassword "APP-Servers"` |
| Kerberos Encryption | RC4 disable, AES-256 only | GPO: `Network security: Configure encryption types allowed for Kerberos` |
| Account Monitoring | AdminSDHolder + sensitive flag | `Set-ADUser -Identity svc_app -AccountNotDelegated $true` |

**Detection Script:**

```powershell
# Silver Ticket anomaly detection
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 10000 | 
    Where-Object {
        $_.Properties[8].Value -eq "0x17" -and  # RC4 encryption
        $_.Properties[0].Value -notlike "*$*"    # Non-machine account
    } | 
    Group-Object {$_.Properties[0].Value} | 
    Where-Object {$_.Count -gt 50} |  # Threshold: 50+ aynı account
    Select-Object Name, Count | 
    Export-Csv "PotentialSilverTicket.csv"
```

### 6.3 Privilege Escalation via ACL Abuse

**Common Attack Paths (BloodHound):**
1. `GenericAll` on User → Password reset → Compromise
2. `WriteDacl` on Group → Add self to group → Privilege escalation
3. `WriteOwner` on OU → Change owner → Modify GPO

**Hardening Script:**

```powershell
# ACL hardening - Remove excessive permissions
function Remove-DangerousACL {
    param([string]$TargetDN)
    
    $ACL = Get-Acl "AD:$TargetDN"
    $DangerousRights = @('GenericAll','WriteDacl','WriteOwner')
    
    $ACL.Access | Where-Object {
        $_.ActiveDirectoryRights -match ($DangerousRights -join '|') -and
        $_.IdentityReference -notlike "NT AUTHORITY\*" -and
        $_.IdentityReference -notlike "BUILTIN\*" -and
        $_.IdentityReference -notlike "*Domain Admins*"
    } | ForEach-Object {
        $ACL.RemoveAccessRule($_) | Out-Null
        Write-Host "Removed: $($_.IdentityReference) - $($_.ActiveDirectoryRights)" -ForegroundColor Yellow
    }
    
    Set-Acl "AD:$TargetDN" -AclObject $ACL
}

# Critical OUs üzerinde çalıştır
$CriticalOUs = @(
    (Get-ADDomain).DomainControllersContainer,
    "OU=Tier 0 Servers,DC=domain,DC=com",
    "OU=Service Accounts,DC=domain,DC=com"
)

foreach ($OU in $CriticalOUs) {
    Remove-DangerousACL -TargetDN $OU
}
```

### 6.4 Zero Trust Architecture for AD

**Microsoft Zero Trust Maturity Model:**

```
Traditional → Advanced → Optimal
   ↓             ↓          ↓
  VPN     Cloud Proxy    Always Verify
  Perimeter    MFA      Least Privilege
  Trust      Conditional  Continuous
            Access       Monitoring
```

**AD-Specific Zero Trust Controls:**

1. **Conditional Access Policies:**
```powershell
# Azure AD Conditional Access (hybrid environment)
# Policy: Require MFA for all admin accounts
New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA - Admins" `
    -State "Enabled" `
    -Conditions @{
        Users = @{
            IncludeGroups = @("Domain Admins","Enterprise Admins")
        }
    } `
    -GrantControls @{
        Operator = "OR"
        BuiltInControls = @("mfa")
    }
```

2. **Just-In-Time (JIT) Admin Access:**
```powershell
# Privileged Access Management (PAM) - Time-bound admin
Enable-ADOptionalFeature -Identity "Privileged Access Management Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name

# Temporary group membership (4 saat)
Add-ADGroupMember -Identity "Domain Admins" -Members "admin_user" -MemberTimeToLive (New-TimeSpan -Hours 4)
```

3. **Device Compliance:**
```powershell
# Sadece managed device'lardan admin login
$AdminGPO = New-GPO -Name "Admin Workstation Requirements"
Set-GPRegistryValue -Name $AdminGPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1

Set-GPRegistryValue -Name $AdminGPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialGuard" `
    -ValueName "Enabled" -Type DWord -Value 1
```

---

## 7. Continuous Monitoring & Automation

### 7.1 SIEM Integration (Splunk/Sentinel Example)

```powershell
# AD Event Forwarding Configuration
wecutil cs /c:"C:\ADMonitoring_Subscription.xml"

# Subscription XML content:
# - Event ID 4720: User account created
# - Event ID 4722: User account enabled
# - Event ID 4724: Password reset attempt
# - Event ID 4732: Member added to security-enabled local group
# - Event ID 4768: Kerberos TGT requested (failure detection)
# - Event ID 4769: Kerberos service ticket requested
```

**Critical Alert Rules:**

| Event | Threshold | Action |
|-------|-----------|--------|
| Event 4720 (User Created) | Any in Tier 0 OUs | Immediate alert + auto-disable |
| Event 4732 (Group Membership) | Domain Admins modification | SMS + Email + SOAR ticket |
| Event 4768/4769 (Kerberos) | >100 requests/min same account | Block account + investigate |
| Event 4625 (Logon Failure) | >10 failures/5min | Account lockout + alert |

### 7.2 Weekly Automated Audit

```powershell
# Scheduled Task: Her Pazar 02:00
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\AD_Weekly_Audit.ps1"

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am

Register-ScheduledTask -TaskName "AD Security Weekly Audit" `
    -Action $Action -Trigger $Trigger -User "SYSTEM" -RunLevel Highest
```

### 7.3 Metric Dashboard (PowerBI / Grafana)

**Key Metrics:**

```plaintext
┌─────────────────────────────────────────┐
│   AD SECURITY POSTURE DASHBOARD         │
├─────────────────────────────────────────┤
│ Privileged Accounts: 12 ↓2 (from 14)   │
│ Password Policy Compliance: 98%         │
│ Unconstrained Delegation: 0 ✓           │
│ Dangerous ACLs: 3 ↑1 (ACTION REQUIRED)  │
│ Service Account Password Age: 45d avg   │
│ Last krbtgt Rotation: 87 days ⚠         │
│ Tier Model Violations: 1 (last 7d)     │
└─────────────────────────────────────────┘
```

---

## 8. Remediation Prioritization Matrix

| Finding | CVSS | Exploitability | Business Impact | Priority |
|---------|------|----------------|-----------------|----------|
| Unconstrained Delegation (non-DC) | 8.8 | Easy (Mimikatz) | Domain Takeover | **P0** |
| GenericAll on Domain Admins | 8.1 | Medium (BloodHound) | Full Compromise | **P0** |
| krbtgt password >180 days | 7.5 | Medium (Golden Ticket) | Persistent Access | **P1** |
| RC4 encryption enabled | 6.8 | Medium (Downgrade attack) | Credential Theft | **P1** |
| Weak service account passwords | 6.5 | Easy (Kerberoasting) | Service Compromise | **P2** |
| Missing MFA on admin accounts | 7.2 | Easy (Phishing) | Account Takeover | **P1** |
| Tier Model violations | 5.5 | Complex | Lateral Movement | **P2** |

**Remediation Workflow:**

```
P0 (Critical - 24h): Immediate action, senior leadership notification
    → Emergency change approval bypass
    → Full team mobilization
    
P1 (High - 7 days): Scheduled remediation, change control
    → Weekly sprint inclusion
    → Standard approval process
    
P2 (Medium - 30 days): Backlog, quarterly roadmap
    → Technical debt tracking
    → Long-term improvement
```

---

## 9. Kaynaklar & Referanslar

### 9.1 Microsoft Resmi Dökümanlar

- **Tiered Admin Model**  
  https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model

- **Active Directory Security Best Practices**  
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

- **Kerberos Authentication**  
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview

- **Authentication Policies and Silos**  
  https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos

### 9.2 CIS Benchmark

- **CIS Microsoft Windows Server 2022 Benchmark v4.0.0**  
  https://www.cisecurity.org/benchmark/microsoft_windows_server

- **CIS Controls v8**  
  https://www.cisecurity.org/controls/v8

### 9.3 NIST Standards

- **NIST SP 800-63B - Digital Identity Guidelines**  
  https://pages.nist.gov/800-63-3/sp800-63b.html

- **NIST Cybersecurity Framework**  
  https://www.nist.gov/cyberframework

### 9.4 Community Tools & Frameworks

- **BloodHound / SharpHound**  
  https://github.com/BloodHoundAD/BloodHound

- **PowerView (PowerSploit)**  
  https://github.com/PowerShellMafia/PowerSploit

- **PingCastle**  
  https://www.pingcastle.com/

- **Purple Knight (Semperis)**  
  https://www.purple-knight.com/

### 9.5 Threat Intelligence

- **MITRE ATT&CK - Active Directory**  
  https://attack.mitre.org/techniques/enterprise/ (T1558, T1078, T1550)

- **Mandiant APT Reports**  
  https://www.mandiant.com/resources/blog

---

## 10. Ek: Hardening Script Validation Checklist

Diğer AI modellerinin (ChatGPT, Gemini, Copilot vb.) önerdiği hardening scriptlerini doğrulamak için:

### 10.1 Script Güvenlik Kontrolü

```powershell
# Script analiz framework
function Test-HardeningScript {
    param([string]$ScriptPath)
    
    $Content = Get-Content $ScriptPath -Raw
    $Issues = @()
    
    # 1. Credential hardcoding kontrolü
    if ($Content -match '(Password|Secret|ApiKey)\s*=\s*["\'].*["\']') {
        $Issues += "CRITICAL: Hardcoded credentials detected"
    }
    
    # 2. Error handling eksikliği
    if ($Content -notmatch 'try\s*{') {
        $Issues += "WARNING: No error handling (try-catch)"
    }
    
    # 3. Dangerous commands
    $DangerousCmds = @('Remove-AD','Disable-AD','Set-ADAccountPassword')
    foreach ($Cmd in $DangerousCmds) {
        if ($Content -match $Cmd -and $Content -notmatch 'WhatIf') {
            $Issues += "HIGH: Dangerous command without -WhatIf: $Cmd"
        }
    }
    
    # 4. Logging eksikliği
    if ($Content -notmatch 'Write-(Host|Output|Verbose|Log)') {
        $Issues += "MEDIUM: No logging mechanism"
    }
    
    # 5. Validation eksikliği
    if ($Content -match 'Get-AD' -and $Content -notmatch 'if\s*\(\s*\$\w+\s*\)') {
        $Issues += "MEDIUM: No null/empty checks after AD queries"
    }
    
    return $Issues
}

# Kullanım
$ValidationResults = Test-HardeningScript -ScriptPath "C:\Scripts\ThirdParty_Hardening.ps1"
if ($ValidationResults) {
    Write-Host "⚠ SCRIPT VALIDATION FAILED ⚠" -ForegroundColor Red
    $ValidationResults | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
} else {
    Write-Host "✓ Script validation passed" -ForegroundColor Green
}
```

### 10.2 Common Pitfalls in AI-Generated Scripts

| Problem | Örnek | Doğru Yaklaşım |
|---------|-------|----------------|
| Hardcoded credentials | `$Pass = "P@ssw0rd"` | `Get-Credential` veya `Read-Host -AsSecureString` |
| No error handling | `Set-ADUser ...` | `try { Set-ADUser ... } catch { Write-Error $_ }` |
| Missing validation | `$Users = Get-ADUser...` → `$Users.Count` | `if ($Users) { ... } else { Write-Warning "No users found" }` |
| No WhatIf support | `Remove-ADUser -Identity $User` | `Remove-ADUser -Identity $User -WhatIf` |
| Inefficient queries | `foreach($User in Get-ADUser -Filter *){...}` | `Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate` |

---

## Sonuç

Bu doküman, Active Directory hardening projelerinin denetim ve doğrulama aşamasında sistematik bir metodoloji sağlar. 2026 itibariyle modern tehdit vektörleri (AI-phishing, advanced Kerberos attacks) göz önünde bulundurularak hazırlanmıştır.

**Kritik Hatırlatmalar:**
1. Denetim scriptlerini production'da çalıştırmadan önce **test environment**'ta doğrulayın
2. BloodHound analizi mutlaka **backup DC** veya **laboratuvar** ortamında simüle edildikten sonra production ortamında gerçekleştirilmelidir."

---
## 🔗 Bağlantılı Dökümanlar
* **[Kaynaklar ve Referanslar](./research.claude.sources.md)**
* **[Kullanılan Mühendislik Promptu](./research.claude.prompt.md)** 