# AD Güvenlik Denetimi ve Analiz Raporu (Audit Analysis)

Bu doküman, `src/hardening.ps1` scripti tarafından gerçekleştirilen denetim (audit) sonuçlarının teknik analizini ve siber güvenlik bulgularını içerir.

## 1. Denetim Özeti (Audit Summary)
* **Hedef Sistem:** siberhuzur.local (Windows Server 2025 Domain Controller).
* **Denetim Tarihi:** 20/01/2026.
* **Kapsam:** Kritik yetki denetimi, şifre politikası analizi ve protokol güvenliği.

## 2. Temel Bulgular ve Risk Analizi

### **Bulgu #1: Kritik Yetki Dağılımı (Privileged Access)**
* **Durum:** `Domain Admins` grubu başarıyla listelenmiştir.
* **Analiz:** Sistemde sadece yetkili `Administrator` hesabı aktif görünmektedir. Bu durum, "En Az Yetki Prensibi" (Principle of Least Privilege) açısından başlangıç aşamasında güvenli bir duruş sergilemektedir.

### **Bulgu #2: Zayıf Şifre Politikası (Password Never Expires)**
* **Risk Seviyesi:** **YÜKSEK (CRITICAL)**.
* **Analiz:** Yapılan denetimde `Administrator` hesabının şifresinin "asla dolmayacak" (PasswordNeverExpires) şekilde ayarlandığı tespit edilmiştir. 
* **Etki:** Şifresi hiç değişmeyen hesaplar, ele geçirilmeleri durumunda saldırganlara sistemde sınırsız süreyle kalıcılık (persistence) sağlar.

### **Bulgu #3: SMBv1 Protokol Açığı**
* **Risk Seviyesi:** **KRİTİK**.
* **Analiz:** Kurulum aşamasında SMBv1 protokolünün açık olduğu varsayılmaktadır.
* **Etki:** WannaCry ve benzeri fidye yazılımlarının (Ransomware) ağ içinde yatayda yayılmasına (Lateral Movement) neden olabilir.

## 3. Uygulanan İyileştirmeler (Remediation)
Script çalıştırıldıktan sonra aşağıdaki "Hardening" adımları ile zafiyetler giderilmiştir:
1. **SMBv1 kapatılarak** ağ katmanı güvenliği sağlanmıştır.
2. **Parola uzunluğu 12 karaktere** zorunlu kılınarak brute-force saldırılarına karşı direnç artırılmıştır.
3. **5 hatalı denemede hesap kilitleme** aktif edilerek parola deneme saldırıları engellenmiştir.

---
*Hazırlayan: BAHA FURKAN YILDIZ*