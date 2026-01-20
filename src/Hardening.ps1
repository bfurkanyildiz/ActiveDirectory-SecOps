<#
    .SYNOPSIS
    Active Directory Hardening & Auditing Script (Final Version)
    
    .DESCRIPTION
    Bu script, İstinye Üniversitesi Bilişim Güvenliği projesi kapsamında:
    1. Kritik yetkileri denetler (Audit).
    2. Güvenlik açıklarını kapatır (Hardening).
    3. Sonuçları raporlar (Reporting).
    
    .AUTHOR
    Baha-Furkan-Yildiz()
#>

# --- 1. ÖN HAZIRLIK VE HATA KONTROLÜ ---
Write-Host "--- SIBERHUZUR AD Güvenlik Modülü Başlatılıyor ---" -ForegroundColor Cyan

# Active Directory Modülü yüklü mü kontrol et
if (!(Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "HATA: Active Directory modülü bulunamadı! Lütfen RSAT araçlarını yükleyin."
    Exit
}
Import-Module ActiveDirectory

# Otomatik olarak mevcut Domain adını al (Hata olmaması için dinamik yapıldı)
$CurrentDomain = (Get-ADDomain).DistinguishedName
$DomainName = (Get-ADDomain).Name
Write-Host "[*] Hedef Domain: $DomainName" -ForegroundColor Gray

# Raporlama için dosya yolu
$ReportFile = "..\docs\Security-Report.txt"
"--- AD SECURITY REPORT - $(Get-Date) ---" | Out-File $ReportFile -Encoding UTF8


# --- 2. AUDIT (DENETİM) AŞAMASI ---
Write-Host "`n[1] AUDIT AŞAMASI BAŞLATILIYOR..." -ForegroundColor Yellow

# A. Domain Adminleri Listele
Write-Host "   [*] Kritik Yetki Kontrolü: Domain Adminler Listeleniyor..." -ForegroundColor Gray
$Admins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
$Admins | Format-Table -AutoSize
$Admins | Out-File $ReportFile -Append

# B. Şifresi Asla Dolmayan Kullanıcıları Bul
Write-Host "   [*] Zayıf Hesap Kontrolü: 'PasswordNeverExpires' olan kullanıcılar aranıyor..." -ForegroundColor Gray
$WeakUsers = Get-ADUser -Filter 'PasswordNeverExpires -eq $true' | Select-Object Name, Enabled
if ($WeakUsers) {
    $WeakUsers | Format-Table -AutoSize
    "UYARI: Şifresi dolmayan kullanıcılar tespit edildi!" | Out-File $ReportFile -Append
    $WeakUsers | Out-File $ReportFile -Append
} else {
    Write-Host "   [OK] Tüm şifre politikaları güvenli görünüyor." -ForegroundColor Green
}


# --- 3. HARDENING (SIKILAŞTIRMA) AŞAMASI ---
Write-Host "`n[2] HARDENING (REMEDIATION) PROTOKOLLERİ UYGULANIYOR..." -ForegroundColor Cyan

# A. SMBv1 Kapat (WannaCry Önlemi) - Senin Kodun
Write-Host "   [+] SMBv1 Protokolü Devre Dışı Bırakılıyor..." -ForegroundColor Green
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null

# B. Güçlü Parola Politikası (Min 12 Karakter) - Senin Kodun (Dinamik Domain ile)
Write-Host "   [+] Parola Politikası Güncelleniyor (Min 12 Karakter)..." -ForegroundColor Green
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -MinPasswordLength 12

# C. Hesap Kilitleme Politikası (Brute-Force Önlemi) - Senin Kodun
Write-Host "   [+] Hesap Kilitleme Politikası Aktif Ediliyor (5 Hata)..." -ForegroundColor Green
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -LockoutThreshold 5


# --- 4. KAPANIŞ VE RAPOR ---
Write-Host "`n-----------------------------------------------------" -ForegroundColor White
Write-Host "AD Başarıyla Sıkılaştırıldı! İspat Tamamlandı." -ForegroundColor Green
Write-Host "Detaylı güvenlik raporu şu adrese kaydedildi: $ReportFile" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------" -ForegroundColor White