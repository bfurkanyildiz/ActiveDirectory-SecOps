# Alan Mimarisi ve Sistem Gereksinimleri (Domain Architecture)

Bu doküman, `siberhuzur.local` domain yapısının teknik altyapısını ve mimari gereksinimlerini tanımlar.

## 1. Sunucu Bilgileri
* **Host Name:** AD-HARDENING-01
* **Operating System:** Windows Server 2025 Standard Core
* **Domain Name:** siberhuzur.local
* **NetBIOS Name:** SIBERHUZUR

## 2. Aktif Servisler ve Roller
* **Active Directory Domain Services (AD DS):** Kimlik yönetimi ve merkezi otorite.
* **DNS Server:** Domain içi çözümleme ve AD replikasyonu için gerekli altyapı.
* **File and Storage Services:** Merkezi dosya paylaşım yönetimi.

## 3. Sistem Gereksinimleri
* **Minimum RAM:** 2 GB (Core kurulum avantajı ile düşük kaynak kullanımı).
* **Network:** Statik IPv4 yapılandırması.