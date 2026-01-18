# Active Directory Hardening & Auditing Teknik Raporu (ChatGPT Deep Research)

## 1. Giriş
Active Directory (AD), kurumların kimlik doğrulama ve yetkilendirme omurgasıdır ve bu
nedenle “hükümetin anahtarları” olarak nitelendirilmektedir . AD
ağları genelde saldırganların başlangıç erişimini elde ettikten sonra hemen hedef aldıkları
kritik bir ortamdır . Örneğin Verizon’un raporu, ihlal olaylarının
%88’inde çalınmış kimlik bilgilerinin rol oynadığını ortaya koymuştur . Bir kere
AD içindeki düşük yetkili bir hesap ele geçirildiğinde, sağlamlaştırılmamış yapılarda kolayca
Domain Admin’e yükselme yolları bulunabilmektedir. Dolayısıyla AD ortamları, geniş
kapsamlı bir saldırı sonrası örgütün tüm ağına erişim sağlayan tehdit vektörleri arasında
yer almaktadır .


## 2. Çalışma Prensibi
* **BloodHound ile Saldırı Yolları**: BloodHound, AD içindeki gizli ilişkileri grafik temelli
analizle ortaya çıkaran bir araçtır . AD’deki kullanıcı/grup üyelikleri,
bilgisayar oturumları ve ACL (erişim kontrol listesi) izinleri gibi ilişkileri Neo4j
veritabanında modelleyerek saldırı yollarını bulur. Örneğin, BloodHound ACL içindeki
GenericAll veya GenericWrite hakları gibi yetkileri takip eder; hatalı yapılandırılmış bir
ACL (ör. bir kullanıcıya fazla yetki verilmesi) kritik erişim yükseltmeleri yaratabilir
. Ayrıca, “Shortest Path to Domain Admins” gibi önceden tanımlı
sorgularla düşük yetkili bir kullanıcının Domain Admin grubuna ulaşabileceği yolları
(grup üyelikleri, yetki tanımları vb. üzerinden) listeler . Unconstrained
delegation (kısıtsız delege) gibi durumlar da BloodHound tarafından tespit edilir; zira
unconstrained delegation’a sahip bir sunucu, servis hesabı olarak sahte TGT
alındığında domain içinde her kullanıcı kimliğini taklit edebilir .

* **Grup Politikaları (GPO)**: AD’de Group Policy Object (GPO) nesneleri, bilgisayar ve
kullanıcı ayarlarını merkezi olarak yönetmek için kullanılır . Bir GPO, ilke
ayarları, güvenlik izinleri ve yönetim kapsamı bilgilerini içeren sanal bir koleksiyondur.
Bu GPO’lar sitelere, alan adlarına veya OU’lara bağlanarak uygulanır ve bilgisayar
açılışında veya kullanıcı oturum açışında devreye girer . GPO suistimali
(Group Policy abuse) ise saldırganların GPO’lar üzerinden zararlı yazılım yayması,
güvenlik önlemlerini devre dışı bırakması veya sistem yapılandırmasını değiştirmesi
demektir . Örneğin, SharpGPOAbuse gibi araçlarla PowerShell ile kayıtlı
görevler (scheduled tasks) yaratıp bütün makinelerde kod çalıştırmak mümkündür

## 3. Teknik Detaylar ve Analiz
* **Zayıf Parola Politikaları:**  Birçok kuruluşta hâlâ 8 karakter veya basit karmaşıklık
kuralları kullanılıyor. Oysaki zayıf veya tekrarlanan parolalar hızla brute-force’a maruz
kalır. Örneğin Specops’a göre, sekiz karakterli basit kurallar saniyeler içinde kırılabilir
. Güncel CIS Windows Server 2022 standartları en az 14 karakterlik parola
ve karmaşıklık (büyük/küçük harf, rakam, sembol) öngörmektedir .

* **Kerberoasting:** Kerberoasting saldırısında, saldırgan düşük seviyeli bir kullanıcı
hesabıyla AD üzerindeki servis hesabı SPN’lerini sorgular, şifresi zayıf olan hizmet
hesaplarının biletlerini alır ve offline kırmaya çalışır . Zayıf veya
değiştirilmeyen hizmet hesabı parolaları bu saldırıyı kolaylaştırır. Microsoft önerilerine
göre bu riski azaltmak için servis hesaplarını gMSA (Group Managed Service Account)
kullanacak şekilde taşımalı, RC4 şifrelemeyi kapatmalı (WS2025’ten itibaren RC4
varsayılan kapalı olacak) ve gereksiz SPN’leri temizlemelisiniz .

* **Hatalı Delege Edilmiş Yetkiler:** Microsoft raporlarına göre, eskimiş
yapılandırmalar veya kötü kontrol eksikliği yüzünden hesaplara gereğinden fazla
izinler verilebilmektedir . Aşırı ayrıcalıklı bir hesap ele geçirildiğinde, bu
hesap güvenlik araçlarını devre dışı bırakmak, kritik verilere ulaşmak veya tüm
domain’i kontrol etmek için kullanılabilir. Özellikle yetkisiz ACL tanımlamaları ve
genişletilmiş izinler riski büyütür. Örneğin, BloodHound’un takip ettiği
GenericAll/GenericWrite gibi ACL hakları ele geçirilirse ciddi ilave erişim sağlanabilir

* **Kısıtsız Delegasyon (Unconstrained Delegation)**: Unconstrained delegasyon, bir
hizmetin servis hesabı olarak sahte TGT almasına izin veren eski bir özellik olup büyük
risktir . Etkinleştirildiğinde servis, her kullanıcı yerine kimlik taklidi yapabilir
ve elde edilen TGT sayesinde domain admin de dahil her servise erişebilir. Microsoft,
bu tür delegasyonu kaldırmayı, kritik hesapları “korumalı kullanıcılar” grubuna
eklemeyi ve etkin bir credential guard kullanmayı önerir .



## 4. Best Practices (En İyi Uygulamalar)
* **Tiered Administration Model:** Microsoft’un Tier 0/1/2 modeli uygulanmalıdır. Tier-0
(Domain Controllers ve kadro/kurum yöneticileri), Tier-1 (sunucu/uygulama
yöneticileri), Tier-2 (istemci bilgisayar yöneticileri) şeklinde ayırın. Üst seviye hesapların
alt seviye makinelerde oturum açmasını kesinlikle engelleyin. Örneğin Domain Admin
hesabı ancak Tier-0 makinelerde kullanılmalı, Tier-1 veya Tier-2 makinelerinde asla
oturum açmamalıdır . Bu yaklaşım “yüksek ayrıcalık hesabı asla daha
düşük ayrıcalık ortamda kullanılmaz” kuralını sağlar .
Yönetim için özel yükseltilmiş hesaplar ve ayrı normal kullanıcı hesapları kullanın, her
admin sadece yapması gereken işlemler için yetkilendirilmelidir
. Yöneticiler için JIT (Just-In-Time) erişim, MFA ve PIM (Privileged Identity
Management) de uygulanarak ayrıcalıklar azaltılabilir . Delegasyon
işlerinizde “Delegation of Control Wizard” ile sadece gereken izinleri verin ve yetkileri
düzenli olarak gözden geçirin .

* **CIS Benchmarks:** Windows Server 2022 için CIS Benchmark’ları uygulayın.
Örneğin parola uzunluğunu en az 14 yapmak, parola karmaşıklığını aktifleştirmek,
parola geçmişini 24’e çıkarmak önerilmektedir . Ayrıca reversibl şifreleme
kullanmayın, hesap kilitlenme eşiğini 5’ten yukarı çıkarmayın ve kilitlenme süresini
yeterince uzun tutun. Domain Controller’lar için ağ üzerinden erişim izinlerini kısıtlayın
(örneğin Access this computer from network hakkı yalnızca Admin ve DC gruplarına
verilmeli) ve “Act as part of operating system” hakkını hiçbir hesaba tanımayın
. LAPS (Local Administrator Password Solution) gibi araçlarla yerel yönetici
parolalarını otomatik döndürerek riskleri azaltabilirsiniz.

* **GPO ve OU Tasarımı**: AD hiyerarşisini anlamlı OUbazlı katmanlara ayırın. Tier-0
varlıkları (DC’ler, hassas işler) ayrı bir OU’da tutun; Tier-1 ve Tier-2 için ayrı OUbazlı
düzen oluşturun. GPO’ları mümkün olduğunca doğrudan OU’a bağlayın, etki alanı
köküne genel GPO bağlamaktan kaçının . ADMX/ADML şablonlarınızı
merkezi bir Policy Definitions deposunda saklayın ve bunlara yalnızca imzalı, güvenli
şablonlar ekleyin . Grup Politikası değişiklikleri için DS Access→Audit GPO
Change altındaki izlemeyi açın, böylece kimin neyi ne zaman değiştirdiğini takip
edebilirsiniz .

* **Diğer Öneriler**: “Yeterli müdahale planı” olmadan uygulanmış sıkı kontroller eksik kalır.
Her DC’den günlük sistem durumu yedekleri alın ve en az bir “soğuk yedek” DC
bulundurun (ağa bağlı olmayan, felaket durumunda devreye alınacak bir kontrolcü)
. Ayrıca sıfır güven (Zero Trust) ilkesiyle sürekli izleme ve anomali tespiti,
aşamalı (phased) uygulamalar ve kapsamlı log analizi gibi modern güvenlik
yaklaşımlarını da benimsediğinizden emin olun .


## 5. Kod Örnekleri (PowerShell Remediation)

Aşağıdaki PowerShell örnekleri, mevcut GPO ve politika yapılarını tarayıp raporlar
oluşturabilir; onay alınırsa düzeltme işlemleri de yapabilir. Örneklerde hata kontrolü için
try/catch blokları ve kullanıcı onayı bulunmaktadır:

# Mevcut GPO'ları tarayıp özel izinleri raporlama
```powershell
try {
    $gpoIssues = @()
    foreach ($gpo in Get-GPO -All) {
        # Örnek: Authenticated Users grubu için GPO-Apply izni kontrolü
        $perm = Get-GPPermissions -Guid $gpo.Id -All | 
                Where-Object { $_.Trustee -eq 'Authenticated Users' -and $_.Permission -eq 'GpoApply' }
        if (!$perm) {
            $gpoIssues += [PSCustomObject]@{GPO = $gpo.DisplayName; Issue = "Authenticated Users missing GpoApply permission"}
        }
    }
    if ($gpoIssues.Count -gt 0) {
        $gpoIssues | Format-Table
    } else {
        Write-Host "Tespit edilecek sorun bulunamadı."
    }
} catch {
    Write-Error "GPO tarama hatası: $_"
}
```
# Bulunan sorunları onay sonrası düzeltme (örneğin eksik izinleri ekleme)
```powershell
if ($gpoIssues.Count -gt 0 -and (Read-Host "Raporlanan sorunları düzeltmek istiyor musunuz? (E/H)") -eq 'E') {
    try {
        foreach ($item in $gpoIssues) {
            $gpo = Get-GPO -Name $item.GPO
            # Örnek düzeltme: Authenticated Users'a GpoApply izni ekleme
            Set-GPPermissions -Guid $gpo.Id -TargetName 'Authenticated Users' `
                             -TargetType Group -PermissionLevel GpoApply -WhatIf:$false
        }
        Write-Host "GPO izinleri güncellendi."
    } catch {
        Write-Error "Düzeltme işlemi sırasında hata: $_"
    }
}
```
# Örnek: Kısıtlı delegasyonu kontrol etme ve kaldırma
```powershell
try {
    $uncDel = Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation
    if ($uncDel) {
        $uncDel | Format-Table Name, TrustedForDelegation
        if ((Read-Host "Unconstrained delegation olan makinelerden delegasyonu kaldır? (E/H)") -eq 'E') {
            foreach ($c in $uncDel) {
                Set-ADComputer -Identity $c.Name -TrustedForDelegation $false
            }
            Write-Host "Kısıtlı delegasyon devre dışı bırakıldı."
        }
    } else {
        Write-Host "Unconstrained delegation tanımlı makine bulunamadı."
    }
} catch {
    Write-Error "Delegasyon kontrolü hatası: $_"
}
```
Her komut bloğu kullanıcı etkileşimine izin vermekte ve hata durumunda mesaj vermektedir. Benzer şekilde, parola politikası gibi ayarları Get-ADDefaultDomainPasswordPolicy ve Set-ADDefaultDomainPasswordPolicy cmdlet’leri ile denetleyebilir ve güncelleyebilirsiniz. Kodlar modüler tutulup önce sadece “-WhatIf” ile test edilerek çalıştırılmalı, gerekirse gerçek düzeltme onayla uygulanmalıdır.

## Yaygın Hatalar

**Önce test etmeme**: Geniş kapsamlı GPO veya parola politikası değişiklikleri laboratuvar ortamında denenmeden dağıtılırsa hizmetlerin (özellikle DC hizmetlerinin) çalışmaz hale gelme riski vardır.

**Aşırı kilitleme**: Çok sıkı hesap kilitleme eşiği (ör. 1-2 yanlışta kilit) veya kritik hesaplara yanlış poliçe uygulanması, yöneticilerin kendilerini kilitlemesine yol açabilir.

**Yetki artıklarını temizlememe**: İhtiyaç kalmayan eski izinler veya ayrılmış ama kullanılmayan servis hesapları temizlenmezse, saldırganlar buralardan içeriyi kolayca suistimal edebilir.

**Geri dönüş planı olmaması**: Sıkılaştırma değişikliklerini almak için yeterli yedekleme veya felaket kurtarma planı olmayan yapılarda hata durumları uzun süren hizmet kesintilerine dönüşür. (AD kadar kritik bir altyapının sürekli yedeklenmesi ve “soğuk DC” bakımı yapılmalıdır.)

## Sonuç

Orta ölçekli bir kurumda (500–1000 kullanıcı) sağlam bir AD mimarisi; çok katmanlı koruma, düzenli denetim ve olağanüstü durum hazırlığı gerektirir. Tiered Administration Model ve en yeni CIS Benchmark önerilerine uygun sıkılaştırma en iyi uygulama olarak görülmelidir. BloodHound gibi araçlarla tespit edilen ACL hataları, delegasyon sorunları ve saldırı yolları hızlıca iyileştirilmelidir. Bunun yanı sıra MFA ve JIT yaklaşımıyla en yüksek ayrıcalıklar sürekli koruma altında tutulmalı, gerekli olmayan delegasyonlar kaldırılmalıdır. Unutulmamalıdır ki, her ne kadar en iyi sıkılaştırma önlemleri alınsa da gerçek güvenlik, aynı zamanda sağlam bir yedekleme ve kurtarma planıyla desteklendiğinde sağlanır; çünkü en iyi korunan AD bile fidye yazılımları veya kaza sonucu yıkımla karşılaşabilir. Bu yaklaşımların tamamı, önerilen kodlu denetim ve otomasyon adımlarıyla birleştirildiğinde orta ölçekli bir ortam için bütünsel bir AD güvenliği mimarisi oluşturulabilir.

## Kaynaklar
Bu raporda kullanılan tüm teknik referanslar, Microsoft dökümantasyonları ve CIS standartlarının detaylı listesine aşağıdaki bağlantıdan ulaşabilirsiniz:

---
## 🔗 Bağlantılı Dökümanlar
* **[Kaynaklar ve Referanslar](./research.chatgpt.sources.md)**
* **[Kullanılan Mühendislik Promptu](./research.chatgpt.prompt.md)** 



