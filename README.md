# KAMUSM E-İmza Kartı ile XML İmzalama

Bu proje, KAMUSM (Kamu Sertifikasyon Merkezi) tarafından verilen e-imza kartları kullanarak XML belgelerini dijital olarak imzalamak için geliştirilmiş bir Python uygulamasıdır. Özellikle e-Arşiv raporları gibi resmi XML belgelerinin imzalanması için tasarlanmıştır.

## Özellikler

- **KAMUSM E-İmza Kartı Desteği**: Atlantis Bilişim ATR29 ve benzeri kart okuyucuları ile uyumlu
- **XML Dijital İmzalama**: XML-DSig standardına uygun enveloped signature oluşturma
- **Çoklu Algoritma Desteği**: Hem RSA hem de Elliptic Curve (ECDSA) sertifikalar desteklenir
- **Otomatik Mekanizma Tespiti**: Kartın desteklediği en uygun imzalama algoritmasını otomatik seçer
- **E-Arşiv Uyumluluğu**: GİB e-Arşiv raporları için optimize edilmiş
- **Debug Araçları**: Kart ve sistem tanımlama için detaylı debug araçları

## Gereksinimler

### Sistem Gereksinimleri
- Windows 10/11 (64-bit)
- Python 3.8 veya üzeri
- KAMUSM E-İmza kartı ve uyumlu kart okuyucu
- Windows Smart Card servisi aktif

### Python Kütüphaneleri
```bash
pip install python-pkcs11 cryptography lxml
```

### Donanım Gereksinimleri
- KAMUSM onaylı e-imza kartı
- USB kart okuyucu (Atlantis Bilişim ATR29 önerilir)
- Aktif internet bağlantısı (sertifika doğrulama için)

## 🛠Kurulum

1. **Projeyi klonlayın**:
```bash
git clone https://github.com/kullanici/AkisSigning.git
cd AkisSigning
```

2. **Sanal ortam oluşturun**:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
```

3. **Bağımlılıkları yükleyin**:
```bash
pip install python-pkcs11 cryptography lxml
```

4. **KAMUSM sürücülerini yükleyin**:
   - KAMUSM'nin resmi web sitesinden en güncel sürücüleri indirin
   - `akisp11.dll` dosyasını `akis_lib/` klasörüne yerleştirin

## Proje Yapısı

```
AkisSigning/
├── main.py                 # Ana uygulama dosyası
├── debug.py                # Debug ve test araçları
├── akis_lib/
│   └── akisp11.dll         # KAMUSM PKCS#11 kütüphanesi
├── signed_earsiv_*.xml     # İmzalanmış XML dosyaları (otomatik oluşur)
├── README.md               # Bu dosya
└── requirements.txt        # Python bağımlılıkları
```

## Kullanım

### Temel Kullanım

1. **E-İmza kartınızı takın** ve kart okuyucunun tanındığından emin olun

2. **Ana uygulamayı çalıştırın**:
```bash
python main.py
```

3. **PIN kodunuzu girin** (istendiğinde)

4. **Uygulama otomatik olarak**:
   - Kartınızı tespit eder
   - Sertifikaları listeler
   - Örnek e-Arşiv XML'ini imzalar
   - İmzalanmış dosyayı kaydeder

### Debug Modu

Kart veya sistem sorunları yaşıyorsanız debug aracını kullanın:

```bash
python debug.py
```

Bu araç:
- Sistem bilgilerini kontrol eder
- Smart Card servislerini test eder
- PKCS#11 kütüphanesi uyumluluğunu kontrol eder
- Farklı imzalama mekanizmalarını test eder

### Özel XML İmzalama

Kendi XML dosyanızı imzalamak için `main.py` dosyasındaki `sample_xml` değişkenini düzenleyin:

```python
sample_xml = '''<?xml version='1.0' encoding='UTF-8'?>
<your-xml-content>
    <!-- Your XML content here -->
</your-xml-content>'''
```

## Yapılandırma

### Kütüphane Yolu
Eğer `akisp11.dll` farklı bir konumdaysa, `main.py` dosyasındaki yolu güncelleyin:

```python
def get_pkcs11_library_path(self):
    lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")
    # Kendi yolunuzu buraya yazın
```

### İmzalama Algoritması
Uygulama otomatik olarak en uygun algoritmayı seçer:
- **ECDSA**: Elliptic Curve sertifikalar için
- **RSA**: RSA sertifikalar için
- **SHA-256**: Hash algoritması olarak

## API Referansı

### KAMUSMCardManagerV2 Sınıfı

#### Temel Metodlar

```python
# Kartı başlat
manager = KAMUSMCardManagerV2()
manager.initialize_card(pin="123456")

# Sertifikaları listele
certificates = manager.list_certificates()

# Özel anahtarları listele
private_keys = manager.list_private_keys()

# XML imzala
signed_xml = manager.sign_xml_document(xml_content)

# Dosyaya kaydet
filename = manager.save_signed_xml(signed_xml)
```

#### Desteklenen İmzalama Mekanizmaları

- `ECDSA` - Ham ECDSA
- `ECDSA_SHA256` - ECDSA ile SHA-256
- `RSA_PKCS` - Ham RSA PKCS#1 v1.5
- `SHA256_RSA_PKCS` - RSA ile SHA-256

## Sorun Giderme

### Yaygın Sorunlar

**"Kart bulunamadı" Hatası**:
- Kartın doğru takıldığını kontrol edin
- Windows Smart Card servisinin çalıştığını kontrol edin
- Debug aracını çalıştırarak kart durumunu kontrol edin

**"PKCS#11 kütüphanesi bulunamadı" Hatası**:
- `akisp11.dll` dosyasının `akis_lib/` klasöründe olduğunu kontrol edin
- KAMUSM sürücülerinin doğru yüklendiğini kontrol edin

**"İmzalama mekanizması hatası"**:
- Kartınızın türünü (RSA/EC) kontrol edin
- Debug aracıyla desteklenen mekanizmaları kontrol edin

**"PIN hatası"**:
- PIN kodunuzun doğru olduğunu kontrol edin
- Kartın bloke olmadığını kontrol edin

### Log Dosyaları

Uygulama detaylı loglar üretir. Sorun yaşadığınızda konsol çıktısını kaydedin:

```bash
python main.py > log.txt 2>&1
```

## Güvenlik

- **PIN kodunuz hiçbir yerde saklanmaz**
- **Özel anahtarlar kart üzerinde kalır**
- **İmzalama işlemi tamamen kart içinde yapılır**
- **Üretilen XML imzaları XML-DSig standardına uygundur**

## Çıktı Formatı

İmzalanmış XML dosyaları şu formatta oluşturulur:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<earsiv:eArsivRaporu xmlns:earsiv="http://earsiv.efatura.gov.tr">
  <!-- Orijinal XML içeriği -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="..."/>
      <ds:SignatureMethod Algorithm="..."/>
      <ds:Reference URI="">
        <ds:Transforms>...</ds:Transforms>
        <ds:DigestMethod Algorithm="..."/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>base64_imza</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>sertifika_base64</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
</earsiv:eArsivRaporu>
```

## Test

Test için örnek XML verisi hazırlanmıştır. Gerçek e-Arşiv raporlarınızı test etmek için XML içeriğini değiştirin.

## Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## Lisans

Bu proje GNU General Public License v3.0 (GPL-3.0) lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasını inceleyebasiniz.

## Destek

Sorun yaşadığınızda:

1. **Debug aracını çalıştırın**: `python debug.py`
2. **Log çıktısını kaydedin**
3. **Issue oluşturun** (GitHub)
4. **KAMUSM teknik desteğine başvurun** (kart sorunları için)

## Referanslar

- [KAMUSM Resmi Web Sitesi](https://kamusm.bilgem.tubitak.gov.tr/)
- [XML-DSig Standardı](https://www.w3.org/TR/xmldsig-core/)
- [PKCS#11 Standardı](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [python-pkcs11 Dokümantasyonu](https://python-pkcs11.readthedocs.io/)

## Sürüm Geçmişi

### v1.0.0 (2025-09-21)
- İlk stabil sürüm
- KAMUSM kart desteği
- XML-DSig imzalama
- EC ve RSA sertifika desteği
- Debug araçları

---

**Geliştirici**: [Adınız]  
**E-posta**: [email@example.com]  
**Proje**: KAMUSM E-İmza XML İmzalama Aracı
