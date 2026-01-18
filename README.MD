# Active Directory Hardening & Auditing (SecOps)

Bu proje,Açık Kaynak Final Projesidir, **Active Directory (AD)** altyapılarındaki yapılandırma hatalarını tespit etmek ve bu hataları **PowerShell** otomasyonu ile sıkılaştırmak (hardening) amacıyla geliştirilen bir güvenlik aracıdır.

## Proje Amacı ve Kapsamı
Windows tabanlı AD ortamlarında saldırganların en çok kullandığı zafiyet noktalarını (GPO hataları, yetki yükseltme yolları vb.) analiz ederek sistemin savunma hattını güçlendirmeyi hedefler.

## Temel Özellikler
* **Bloodhound Analizi:** AD nesneleri arasındaki ilişkileri ve olası saldırı vektörlerini haritalandırır.
* **GPO Güvenlik Denetimi:** Zayıf şifre politikaları ve hatalı yapılandırılmış grup politikalarını bulur.
* **Yetki Yönetimi:** Domain Admins gibi kritik gruplardaki gereksiz yetkili hesapları listeler.
* **Otomatik İyileştirme (Remediation):** Tespit edilen açıklar için hazır PowerShell sıkılaştırma scriptleri sunar.

## Teknik Altyapı
* **Platform:** Windows Server 2022 / Windows 10 & 11
* **Kullanılan Diller:** PowerShell 5.1+, C#
* **Kategori:** SecOps / Pentesting / Forensic

## Klasör Yapısı
* **`researchs/`**: Gemini, ChatGPT ve Claude üzerinden yapılan derin teknik araştırma çıktıları.
* **`specs/`**: Projenin teknik gereksinimleri.
* **`src/`**: Geliştirilen ana scriptler ve kod dosyaları.
* **`docs/`**: Kurulum rehberi ve kullanım dökümanları.

## Başlangıç
Bu projeyi test etmek için yerel makinenize clone'layabilirsiniz:
`git clone https://github.com/bfurkan-yildiz/ActiveDirectory-SecOps.git`

## Hazırlayan
* **Baha Furkan Yıldız** - İstinye Üniversitesi Bilişim Güvenliği Teknolojisi