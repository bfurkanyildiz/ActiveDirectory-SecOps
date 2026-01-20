# Güvenlik Sıkılaştırma Standartları (Hardening Standards)

Proje kapsamında uygulanan güvenlik protokolleri, NIST ve CIS standartları baz alınarak yapılandırılmıştır.

## 1. Kimlik ve Erişim Yönetimi (IAM)
* **S-001 (Password Complexity):** Tüm domain kullanıcıları için minimum 12 karakter zorunluluğu.
* **S-002 (Lockout Policy):** Brute-force saldırılarını engellemek adına 5 hatalı girişte hesap kilitleme.

## 2. Ağ ve Protokol Güvenliği
* **S-003 (Protocol Disabling):** WannaCry ve benzeri fidye yazılımlarının yayılmasını önlemek için SMBv1 protokolünün tamamen devre dışı bırakılması.

## 3. Denetim ve Raporlama (Auditing)
* **S-004 (Privilege Audit):** Domain Admins grubunun düzenli olarak listelenmesi ve yetkisiz hesap artışının denetlenmesi.