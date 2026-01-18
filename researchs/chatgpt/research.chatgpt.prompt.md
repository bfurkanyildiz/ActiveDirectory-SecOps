# ChatGPT Deep Research Promptları

Bu dosya, Active Directory Hardening araştırması sırasında ChatGPT (Deep Research Mode) modeline verilen komutları ve yönlendirmeleri içerir.

## 1. Ana Komut (Master Prompt) 
**Hedef:** Teknik Analiz ve PowerShell Otomasyonu

> "Merhaba, Active Directory Hardening projem için 'Derin Araştırma' (Deep Research) modunda çalışmanı istiyorum. Lütfen bulduğun ilk sonuçlarla yetinme; referansların içindeki teknik dökümanları ve güncel güvenlik standartlarını (2025-2026) tarayarak ilerle.
>
> **Araştırma Konusu:** Active Directory Ortamlarında GPO Sıkılaştırma, Yetki Yönetimi (Privileged Access) ve Bloodhound Analiz Sonuçlarının Remediation (İyileştirme) Süreçleri.
>
> **Yapılandırılmış Çıktı Beklentisi:** Giriş, Çalışma Prensibi, Teknik Detaylar, Best Practices, Kod Örnekleri, Yaygın Hatalar ve Sonuç.
>
> **Önemli Not:** her teknik bilginin kaynağını link olarak belirtmeni istiyorum."

## 2. Derinleştirme ve Kapsam Belirleme (2. Prompt)
ChatGPT'nin araştırmayı netleştirmek adına sorduğu sorular üzerine, projenin teknik sınırları aşağıdaki komutla belirlenmiştir:

> "Derinleştirme soruların için teşekkürler, işte projemin teknik parametreleri:
> 
> 1. **Hedef Ortam:** Orta ölçekli bir kurumsal yapı simülasyonu (500-1000 kullanıcı arası).
> 2. **BloodHound Odağı:** Özellikle 'ACL Misconfigurations', 'Unconstrained Delegation' ve 'Path to Domain Admin' gibi kritik yetki yükseltme yollarına odaklanmanı istiyorum.
> 3. **PowerShell Script Yapısı:** Scriptlerin önce mevcut GPO/Policy yapılarını tarayıp raporlamasını, ardından onay ile düzeltme (remediation) yapabilecek modüler bir yapıda olmasını tercih ederim.
> 4. **CIS Benchmark:** En güncel standart olan Windows Server 2022 sürümünü baz alabilirsin."

---
*Bu iki aşamalı prompt yapısı, modelin 2025-2026 güncel güvenlik standartlarına (CIS v4.0.0) ve Microsoft'un modern katmanlı yönetim modellerine ulaşmasını sağlamıştır.*