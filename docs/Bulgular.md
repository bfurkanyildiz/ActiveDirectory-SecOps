# Active Directory Zafiyet Analizi ve Sıkılaştırma (Hardening) Laboratuvarı

Bu doküman, Windows Server üzerinde gerçekleştirilen sızma testi simülasyonu ve ardından uygulanan güvenlik sıkılaştırma adımlarını içermektedir.

## 🔍 Keşfedilen Zafiyetler ve Bulgular

### 1. LLMNR ve NBNS Zehirlemesi (Ağ Bağırması)
* **Bulgu:** Kullanıcı ağda mevcut olmayan bir adrese (`\\uydurma-adres`) gitmeye çalıştığında, Windows'un LLMNR ve NBNS protokolleri üzerinden ağa yayın yaptığı gözlemlendi.
* **Risk:** Saldırgan (Kali Linux/Responder), bu yayınlara sahte yanıtlar vererek kullanıcıyı kendine yönlendirebilir.

### 2. Zayıf Parola Politikası (Weak Password)
* **Bulgu:** Başlangıçta oluşturulan `vboxuser` kullanıcısının şifresi `123` gibi çok basit bir değer olarak belirlenebildi.
* **Risk:** Ele geçirilen NTLMv2 hash bilgisi, John the Ripper gibi araçlarla saniyeler içinde kırılarak tam yetkili erişim sağlandı.

### 3. Otomatik Hash Paylaşımı (SSO Riskleri)
* **Bulgu:** Windows'un kullanıcıyı yormamak için oturum açma bilgilerini ağdaki isteklere otomatik sunması (Single Sign-On), kullanıcı daha şifre girmeden hash bilgisinin saldırganın ekranına düşmesine neden oldu.

### 4. Miras Kalan (Legacy) Kullanıcı Açığı
* **Bulgu:** Güvenlik scripti (Hardening) uygulandıktan sonra bile, önceden oluşturulmuş zayıf şifreli kullanıcıların oturumlarının korunmaya devam ettiği fark edildi.
* **Risk:** Sıkılaştırma adımları geriye dönük olarak mevcut şifreleri zorla değiştirmediği için "açık kapı" riskinin devam ettiği gözlemlendi.

---

## 🛡️ Uygulanan Savunma Adımları (Hardening)

### 1. Parola Sıkılaştırma (GPO)
PowerShell üzerinden uygulanan script ile aşağıdaki kurallar getirildi:
* **Minimum Parola Uzunluğu:** 12 Karakter.
* **Karmaşıklık Gereksinimi:** Büyük/küçük harf, rakam ve sembol zorunluluğu.
* **Hesap Kilitleme:** 5 hatalı denemede hesabın otomatik kilitlenmesi.

### 2. SMB Signing (İmzalama)
* Sunucu ile istemci arasındaki iletişimin dijital olarak imzalanması zorunlu kılındı. Bu sayede Responder gibi araçların araya girmesi engellendi.

### 3. Protokol Devre Dışı Bırakma
* GPO üzerinden **LLMNR** kapatıldı ve ağ kartı ayarlarından **NetBIOS over TCP/IP** devre dışı bırakıldı.

---

## 🚀 Sonuç
Hardening adımları sonrası, saldırgan ağ trafiğini dinlese dahi şifre hash bilgilerine ulaşması zorlaştırılmış, ulaşsa bile karmaşık şifre politikası nedeniyle şifrenin kırılması (Brute-Force) teknik olarak imkansız hale getirilmiştir.