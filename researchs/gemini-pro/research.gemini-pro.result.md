# EXECUTIVE STRATEGIC & TECHNICAL RESEARCH SYNTHESIS: AD HARDENING (PHASE 1)

**Proje:** Active Directory Hardening & Auditing
**Hazırlayan:** CISO & Enterprise Architect Office

---

## 1. Gap Analysis: Mevcut Durum (Legacy) vs. Hedef Mimari (Tiered)

Bu analiz, organizasyonun mevcut "Flat" (Düz) Active Directory yapısı ile hedeflenen "Tiered" (Katmanlı) yönetim modeli arasındaki güvenlik ve operasyonel uçurumları teknik olarak ortaya koymaktadır.

### 1.1. Mimari Karşılaştırma

| Özellik | Mevcut Durum (Flat AD) | Hedef Durum (Tiered Admin Model / Enterprise Access Model) | Risk Analizi |
| --- | --- | --- | --- |
| **Yetki Dağıtımı** | Tüm Domain Adminler (DA) her sunucu ve workstation'a erişebilir. | **Tier 0 (Identity):** Sadece DC'ler ve PKI.<br>

<br>**Tier 1 (Servers):** Uygulama sunucuları.<br>

<br>**Tier 2 (Workstations):** Son kullanıcı cihazları. | Flat yapıda, bir Tier 2 cihazının ele geçirilmesi, *Pass-the-Hash* veya *Token Impersonation* yoluyla doğrudan Domain Admin yetkisine yükselmeye (Privilege Escalation) izin verir. |
| **Credential Hygiene** | DA hesapları cache'lenmiş credential olarak workstation'larda bulunabilir. | Tier 0 hesapları ASLA Tier 1 veya Tier 2 cihazlara login olamaz (Technical Enforcement via GPO/Authentication Silos). | DA credential hırsızlığı riski %90+ oranında elimine edilir. |
| **Yönetim Arabirimi** | Standart kullanıcı bilgisayarlarından RDP/RSAT kullanımı. | **Privileged Access Workstations (PAW)** veya **Secure Jump Servers** zorunluluğu. | Keylogger veya malware enfekte olmuş kullanıcı bilgisayarından yönetim yapılması engellenir. |

### 1.2. Konfigürasyon Sapması (Configuration Drift)

Zaman içinde manuel müdahalelerle oluşan "Drift", hardening projelerinin en büyük düşmanıdır.

* **Risk:** "Temporary" olarak verilen yetkilerin geri alınmaması, GPO'ların "Block Inheritance" ile devre dışı bırakılması.
* **Strateji:** Infrastructure as Code (IaC) prensipleri AD'ye uygulanmalı (DSC - Desired State Configuration) ve anlık drift tespiti yapılmalıdır.

---

## 2. 2026 Gelişmiş Tehdit Matrisi (Advanced Threat Matrix)

NIST CSF 2.0 (Identify, Protect, Detect, Respond, Recover) çerçevesinde, modern saldırı vektörlerine karşı geliştirilen savunma matrisi aşağıdadır.

| Tehdit Vektörü | Saldırı Tekniği (TTPs) | NIST CSF 2.0 Odak | Savunma Katmanı (Mitigation Strategy) |
| --- | --- | --- | --- |
| **AI-Powered Phishing & Social Engineering** | Deepfake ses/görüntü ile Helpdesk'i manipüle ederek şifre sıfırlama veya MFA bypass. | **PROTECT** | **FIDO2 / Hardware Key Enforcement:** Phishable olmayan MFA kullanımı.<br>

<br>**Strict Helpdesk Verification:** Kullanıcı doğrulama protokollerinin (Manager Approval vb.) sıkılaştırılması. |
| **Advanced Kerberos Attacks** | **Silver Ticket Variants:** Servis hesaplarının hash'ini kullanarak TGS üretme. PAC Validation bypass girişimleri. | **DETECT / RESPOND** | **Kerberos Armoring (FAST):** Offline dictionary saldırılarını engelleme.<br>

<br>**gMSA (Group Managed Service Accounts):** Otomatik şifre rotasyonu (120 karakter).<br>

<br>**Privileged Attribute Certificate (PAC) Validation:** Zorunlu hale getirme. |
| **Lateral Movement** | **Overpass-the-Hash / Pass-the-Ticket:** NTLM devre dışı olsa bile Kerberos ticket manipülasyonu ile yatay hareket. | **PROTECT / DETECT** | **Authentication Silos & Policies:** Tier geçişlerinin teknik olarak bloklanması.<br>

<br>**Micro-segmentation:** DC'lere erişimin sadece gerekli portlar ve IP bloklarından (PAW) izin verilmesi. |
| **Shadow Admins** | Doğrudan admin grubunda olmayan ama ACL (Access Control List) üzerinden kritik objelere "Write/Reset Password" yetkisi olan hesaplar. | **IDENTIFY** | **AD ACL Auditing:** AdminSDHolder ve kritik obje ACL'lerinin düzenli taranması (BloodHound/SharpHound analizi). |

---

## 3. Bütünleşik Hardening & Auditing İş Akışı (Looping Mechanism)

Hardening tek seferlik bir proje değil, sürekli bir "Configuration State Enforcement" döngüsüdür.

1. **Baseline Establishment (Referans Belirleme):** CIS Benchmark Level 1 & 2 ve Microsoft Security Baseline kullanılarak "Altın İmaj" GPO setlerinin oluşturulması.
2. **Enforcement (Uygulama):** Politikaların OU bazlı (Tier yapısına uygun) uygulanması.
3. **Real-time Monitoring (İzleme):** Domain Controller Security Event Loglarının (Event ID 4732, 4768, 4769, 4728 vb.) SIEM'e (Sentinel/Splunk) akıtılması.
4. **Audit & Feedback (Denetim ve Geri Besleme):**
* Değişikliklerin otomatik tespiti (Change Tracking).
* Uyumsuzluk durumunda (Non-compliant), otomasyonun GPO'yu tekrar "Enforce" etmesi veya alarm üretmesi.


5. **Remediation (İyileştirme):** Vulnerability assessment (Örn: PingCastle) raporlarına göre baseline'ın güncellenmesi.

*Bu döngü, statik bir güvenliği değil, dinamik ve kendini iyileştiren (Self-Healing) bir AD yapısını hedefler.*

---

## 4. 3 Haftalık Detaylı Uygulama Yol Haritası

### Hafta 1: Görünürlük, Envanter ve Temizlik (Discovery & Hygiene)

* **Gün 1-2:** Active Directory Health Check (DCDiag, Replication analizi). Tüm stale (atıl) hesapların (90+ gün login olmayan) ve cihazların tespiti ve disable edilmesi.
* **Gün 3-4:** Servis Hesapları (Service Accounts) envanterinin çıkarılması. SPN (Service Principal Name) taraması yapılarak Kerberoastable hesapların belirlenmesi.
* **Gün 5:** Privilege Access Discovery. "Domain Admins", "Enterprise Admins" ve "Schema Admins" gruplarındaki gereksiz üyelerin temizlenmesi. Shadow Admin analizi (BloodHound).

### Hafta 2: İzolasyon ve Tier Modelinin İnşası (Architecture & Segmentation)

* **Gün 1-2:** Tier 0, Tier 1 ve Tier 2 OU (Organizational Unit) yapısının oluşturulması.
* **Gün 3:** GPO Hardening. Legacy protokollerin (NTLMv1, SMBv1, WDigest) devre dışı bırakılması.
* **Gün 4-5:** PAW (Privileged Access Workstation) konseptinin pilot uygulaması. Tier 0 yöneticileri için "Logon Rights" kısıtlamalarının (Deny log on as a batch job/service/locally) GPO ile tanımlanması.

### Hafta 3: Otomasyon, Denetim ve İzleme (Automation & Auditing)

* **Gün 1-2:** LAPS (Local Administrator Password Solution) deployment'ı veya modernizasyonu (Windows LAPS). Tüm Tier 2 makinelerde lokal admin şifrelerinin tekilleştirilmesi.
* **Gün 3:** Denetim politikalarının (Advanced Audit Policy Configuration) açılması. Kritik objeler için SACL (System Access Control Lists) tanımlanması.
* **Gün 4-5:** Honeytoken hesapların (tuzak hesaplar) oluşturulması ve bu hesaplara yönelik erişim girişimleri için SIEM alarmlarının yazılması. Proje kapanış raporu ve sonraki adımlar.

---

## 5. KPI ve Başarı Metrikleri (Success Metrics)

Projenin başarısı aşağıdaki somut teknik metriklerle ölçülecektir:

* **Identity Exposure Score:** PingCastle veya Purple Knight skoru **< 20** (Düşük Risk) seviyesine çekilmeli.
* **Privileged Account Reduction:** Domain Admin sayısı **<= 5** (Hedef: Just-in-Time Access ile 0 daimi admin).
* **KRBTGT Rotation:** KRBTGT hesap şifresinin son değiştirilme tarihi **< 180 gün** (Düzenli rotasyon scripti aktif).
* **Legacy Protocol Usage:** NTLMv1 ve SMBv1 trafiği **0 (Sıfır)**.
* **Ticket Lifetime:** Ticket Granting Ticket (TGT) maksimum ömrü **10 saat**.
* **Mean Time to Detect (MTTD):** Yetkili grup üyelik değişikliklerinin tespit süresi **< 5 dakika**.

---

### Bibliyografya (Referanslar)

1. *National Institute of Standards and Technology (NIST).* (2024). **NIST Cybersecurity Framework (CSF) 2.0**.
2. *Center for Internet Security (CIS).* (2024). **CIS Benchmarks for Microsoft Windows Server 2019/2022**.
3. *Microsoft Security.* (2023). **Enterprise Access Model (formerly Tier Model)** & **Securing Privileged Access**.
4. *ANSSI (Agence nationale de la sécurité des systèmes d'information).* (2021). **Recommendations for Secure Administration of Active Directory**.

---
## 🔗 Bağlantılı Dökümanlar
* **[Kaynaklar ve Referanslar](./research.gemini-pro.sources.md)**
* **[Kullanılan CISO Master Promptu](./research.gemini-pro.prompt.md)**