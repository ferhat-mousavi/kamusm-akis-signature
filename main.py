#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAMUSM E-İmza Kartı python-pkcs11 ile XML İmzalama
Gerekli kütüphaneler: pip install python-pkcs11 cryptography lxml
"""

import pkcs11
import os
import base64
from datetime import datetime
import hashlib
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class KAMUSMCardManagerV2:
    def __init__(self):
        self.lib = None
        self.session = None
        self.token = None

    def get_pkcs11_library_path(self):
        """PKCS#11 kütüphanesinin yolunu döndür"""
        lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

        if os.path.exists(lib_path):
            print(f"PKCS#11 kütüphanesi bulundu: {lib_path}")
            return lib_path
        else:
            raise FileNotFoundError(f"PKCS#11 kütüphanesi bulunamadı: {lib_path}")

    def initialize_card(self, pin=None):
        """Kartı başlat"""
        try:
            lib_path = self.get_pkcs11_library_path()
            print(f"PKCS#11 kütüphanesi: {lib_path}")

            # Kütüphaneyi yükle
            self.lib = pkcs11.lib(lib_path)
            print("✓ Kütüphane başarıyla yüklendi")

            # Slotları al
            slots = self.lib.get_slots()
            print(f"Bulunan slot sayısı: {len(slots)}")

            if not slots:
                raise Exception("Hiç slot bulunamadı")

            # Token bulunan slotu bul
            token_slot = None
            for slot in slots:
                try:
                    token = slot.get_token()
                    print(f"Slot: {slot}, Token: {token.label}")
                    if token.label and token.label.strip():  # Token varsa
                        token_slot = slot
                        self.token = token
                        break
                except:
                    continue

            if not token_slot:
                raise Exception("Token bulunan slot yok")

            print(f"Kullanılacak token: {self.token.label}")
            print(f"Token bilgileri:")
            print(f"  Üretici: {self.token.manufacturer_id}")
            print(f"  Model: {self.token.model}")

            # Token'ın diğer özelliklerini güvenli şekilde al
            try:
                print(f"  Seri No: {self.token.serial_number}")
            except AttributeError:
                print(f"  Seri No: Bilgi mevcut değil")

            try:
                print(f"  Donanım Ver: {self.token.hardware_version}")
                print(f"  Firmware Ver: {self.token.firmware_version}")
            except AttributeError:
                print(f"  Sürüm bilgileri mevcut değil")

            # Oturum aç
            if pin:
                try:
                    self.session = self.token.open(user_pin=pin)
                    print("✓ PIN ile oturum açıldı")
                except Exception as e:
                    print(f"PIN ile oturum açma hatası: {e}")
                    # PIN olmadan da dene
                    self.session = self.token.open()
                    print("✓ PIN olmadan oturum açıldı")
            else:
                self.session = self.token.open()
                print("✓ PIN olmadan oturum açıldı")

            return True

        except Exception as e:
            print(f"Kart başlatma hatası: {e}")
            import traceback
            traceback.print_exc()
            return False

    def list_certificates(self):
        """Karttaki sertifikaları listele"""
        try:
            if not self.session:
                raise Exception("Oturum açılmamış")

            # Sertifikaları bul
            certificates = []
            cert_objects = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE
            }))

            print(f"\nBulunan sertifika sayısı: {len(cert_objects)}")

            for i, cert_obj in enumerate(cert_objects):
                try:
                    # Sertifika verilerini al
                    cert_der = cert_obj[pkcs11.Attribute.VALUE]

                    # X.509 sertifikasına dönüştür
                    cert = x509.load_der_x509_certificate(cert_der)

                    print(f"\n--- Sertifika {i + 1} ---")
                    print(f"Konu: {cert.subject}")
                    print(f"Veren: {cert.issuer}")
                    print(f"Geçerlilik: {cert.not_valid_before} - {cert.not_valid_after}")
                    print(f"Seri No: {cert.serial_number}")

                    certificates.append({
                        'object': cert_obj,
                        'certificate': cert,
                        'der_data': cert_der
                    })

                except Exception as e:
                    print(f"Sertifika {i + 1} okunamadı: {e}")

            return certificates

        except Exception as e:
            print(f"Sertifika listeleme hatası: {e}")
            return []

    def list_private_keys(self):
        """Karttaki özel anahtarları listele"""
        try:
            if not self.session:
                raise Exception("Oturum açılmamış")

            # Özel anahtarları bul
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))

            print(f"\nBulunan özel anahtar sayısı: {len(private_keys)}")

            key_info = []
            for i, key_obj in enumerate(private_keys):
                try:
                    # Attribute'ları farklı yöntemlerle dene
                    try:
                        key_type = key_obj[pkcs11.Attribute.KEY_TYPE]
                    except:
                        key_type = "Bilinmiyor"

                    try:
                        key_id = key_obj[pkcs11.Attribute.ID]
                    except:
                        key_id = b""

                    try:
                        label = key_obj[pkcs11.Attribute.LABEL]
                    except:
                        label = ""

                    print(f"\n--- Özel Anahtar {i + 1} ---")
                    print(f"Tip: {key_type}")
                    print(f"ID: {key_id.hex() if key_id else 'N/A'}")
                    print(f"Etiket: {label}")

                    key_info.append({
                        'object': key_obj,
                        'type': key_type,
                        'id': key_id,
                        'label': label
                    })

                except Exception as e:
                    print(f"Anahtar {i + 1} bilgisi alınamadı: {e}")
                    # Bilgi alamasak bile anahtarı listeye ekle
                    key_info.append({
                        'object': key_obj,
                        'type': 'Bilinmiyor',
                        'id': b'',
                        'label': f'Anahtar_{i + 1}'
                    })

            return key_info

        except Exception as e:
            print(f"Özel anahtar listeleme hatası: {e}")
            return []

    def sign_data(self, data, private_key_obj=None):
        """Veri imzala"""
        try:
            if not self.session:
                raise Exception("Oturum açılmamış")

            if not private_key_obj:
                # İlk özel anahtarı kullan
                private_keys = self.list_private_keys()
                if not private_keys:
                    raise Exception("Özel anahtar bulunamadı")
                private_key_obj = private_keys[0]['object']

            # Veriyi hazırla
            if isinstance(data, str):
                data = data.encode('utf-8')

            # EC (Elliptic Curve) ve RSA mekanizmalarını dene
            mechanisms_to_try = [
                # EC mekanizmaları
                (pkcs11.Mechanism.ECDSA, True),  # Ham ECDSA + manuel hash
                (pkcs11.Mechanism.ECDSA_SHA1, False),  # ECDSA ile SHA1
                (pkcs11.Mechanism.ECDSA_SHA256, False),  # ECDSA ile SHA256
                # RSA mekanizmaları (backup)
                (pkcs11.Mechanism.RSA_PKCS, True),  # Ham RSA + manuel hash
                (pkcs11.Mechanism.SHA1_RSA_PKCS, False),  # SHA1 ile RSA
                (pkcs11.Mechanism.SHA256_RSA_PKCS, False),  # SHA256 ile RSA
            ]

            for mechanism, manual_hash in mechanisms_to_try:
                try:
                    if manual_hash:
                        # Manuel hash için
                        digest = hashlib.sha256(data).digest()
                        signature = private_key_obj.sign(digest, mechanism=mechanism)
                    else:
                        # Otomatik hash için
                        signature = private_key_obj.sign(data, mechanism=mechanism)

                    print(f"\nİmzalama başarılı! (Mekanizma: {mechanism})")
                    print(f"Orijinal veri boyutu: {len(data)} byte")
                    print(f"İmza boyutu: {len(signature)} byte")
                    print(f"İmza (hex): {signature.hex()[:100]}...")

                    return signature, mechanism

                except Exception as mech_error:
                    print(f"Mekanizma {mechanism} başarısız: {mech_error}")
                    continue

            raise Exception("Hiçbir imzalama mekanizması çalışmadı")

        except Exception as e:
            print(f"İmzalama hatası: {e}")
            import traceback
            traceback.print_exc()
            return None, None

    def sign_xml_document(self, xml_content, private_key_obj=None, certificate=None):
        """XML belgesini dijital imzala"""
        try:
            if not self.session:
                raise Exception("Oturum açılmamış")

            if not private_key_obj:
                private_keys = self.list_private_keys()
                if not private_keys:
                    raise Exception("Özel anahtar bulunamadı")
                private_key_obj = private_keys[0]['object']

            if not certificate:
                certificates = self.list_certificates()
                if not certificates:
                    raise Exception("Sertifika bulunamadı")
                certificate = certificates[0]['certificate']

            # XML'i parse et
            if isinstance(xml_content, str):
                xml_content = xml_content.encode('utf-8')

            root = etree.fromstring(xml_content)

            # XML-DSig namespace'lerini tanımla
            dsig_ns = "http://www.w3.org/2000/09/xmldsig#"
            etree.register_namespace("ds", dsig_ns)

            # Signature elementini oluştur
            signature_elem = etree.SubElement(root, f"{{{dsig_ns}}}Signature")
            signature_elem.set("Id", "signature")

            # SignedInfo elementi
            signed_info = etree.SubElement(signature_elem, f"{{{dsig_ns}}}SignedInfo")

            # CanonicalizationMethod
            canon_method = etree.SubElement(signed_info, f"{{{dsig_ns}}}CanonicalizationMethod")
            canon_method.set("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

            # SignatureMethod
            sig_method = etree.SubElement(signed_info, f"{{{dsig_ns}}}SignatureMethod")
            sig_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha256")

            # Reference
            reference = etree.SubElement(signed_info, f"{{{dsig_ns}}}Reference")
            reference.set("URI", "")

            # Transforms
            transforms = etree.SubElement(reference, f"{{{dsig_ns}}}Transforms")
            transform1 = etree.SubElement(transforms, f"{{{dsig_ns}}}Transform")
            transform1.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            transform2 = etree.SubElement(transforms, f"{{{dsig_ns}}}Transform")
            transform2.set("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

            # DigestMethod
            digest_method = etree.SubElement(reference, f"{{{dsig_ns}}}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

            # Orijinal XML'in hash'ini hesapla
            original_xml_copy = etree.fromstring(xml_content)
            canonical_xml = etree.tostring(original_xml_copy, method="c14n")

            # SHA-256 hash
            digest_value = hashlib.sha256(canonical_xml).digest()
            digest_value_b64 = base64.b64encode(digest_value).decode()

            # DigestValue
            digest_value_elem = etree.SubElement(reference, f"{{{dsig_ns}}}DigestValue")
            digest_value_elem.text = digest_value_b64

            # SignedInfo'yu kanonikalize et ve imzala
            signed_info_canonical = etree.tostring(signed_info, method="c14n")

            # EC ve RSA mekanizmalarını dene
            mechanisms_to_try = [
                # EC mekanizmaları (öncelik)
                (pkcs11.Mechanism.ECDSA, True),  # Ham ECDSA + manuel hash
                (pkcs11.Mechanism.ECDSA_SHA1, False),  # ECDSA ile SHA1
                (pkcs11.Mechanism.ECDSA_SHA256, False),  # ECDSA ile SHA256
                # RSA mekanizmaları (backup)
                (pkcs11.Mechanism.RSA_PKCS, True),  # Ham RSA + manuel hash
                (pkcs11.Mechanism.SHA1_RSA_PKCS, False),  # SHA1 ile RSA
                (pkcs11.Mechanism.SHA256_RSA_PKCS, False),  # SHA256 ile RSA
            ]

            signature_bytes = None
            used_mechanism = None

            for mechanism, manual_hash in mechanisms_to_try:
                try:
                    if manual_hash:
                        # Manuel hash ile
                        signed_info_hash = hashlib.sha256(signed_info_canonical).digest()
                        signature_bytes = private_key_obj.sign(signed_info_hash, mechanism=mechanism)
                    else:
                        # Otomatik hash ile
                        signature_bytes = private_key_obj.sign(signed_info_canonical, mechanism=mechanism)

                    used_mechanism = mechanism
                    print(f"XML İmzalama başarılı! Kullanılan mekanizma: {mechanism}")
                    break

                except Exception as mech_error:
                    print(f"XML Mekanizma {mechanism} başarısız: {mech_error}")
                    continue

            if not signature_bytes:
                raise Exception("Hiçbir XML imzalama mekanizması çalışmadı")

            signature_b64 = base64.b64encode(signature_bytes).decode()

            # SignatureMethod'u kullanılan mekanizmaya göre güncelle
            if used_mechanism in [pkcs11.Mechanism.ECDSA, pkcs11.Mechanism.ECDSA_SHA1, pkcs11.Mechanism.ECDSA_SHA256]:
                sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
            else:
                sig_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha256")

            # SignatureValue
            signature_value = etree.SubElement(signature_elem, f"{{{dsig_ns}}}SignatureValue")
            signature_value.text = signature_b64

            # KeyInfo
            key_info = etree.SubElement(signature_elem, f"{{{dsig_ns}}}KeyInfo")
            x509_data = etree.SubElement(key_info, f"{{{dsig_ns}}}X509Data")
            x509_cert = etree.SubElement(x509_data, f"{{{dsig_ns}}}X509Certificate")

            # Sertifikayı base64 encode et
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode()
            x509_cert.text = cert_b64

            # İmzalanmış XML'i döndür
            signed_xml = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=True)

            print("\n=== XML İmzalama Başarılı ===")
            print(f"Orijinal XML boyutu: {len(xml_content)} byte")
            print(f"İmzalanmış XML boyutu: {len(signed_xml)} byte")
            print(f"Digest değeri: {digest_value_b64}")
            print(f"İmza değeri: {signature_b64[:50]}...")

            return signed_xml.decode('utf-8')

        except Exception as e:
            print(f"XML imzalama hatası: {e}")
            import traceback
            traceback.print_exc()
            return None

    def save_signed_xml(self, signed_xml_content, filename=None):
        """İmzalanmış XML'i dosyaya kaydet"""
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"signed_earsiv_{timestamp}.xml"

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(signed_xml_content)

            print(f"İmzalanmış XML kaydedildi: {filename}")
            return filename

        except Exception as e:
            print(f"Dosya kaydetme hatası: {e}")
            return None

    def close(self):
        """Bağlantıyı kapat"""
        try:
            if self.session:
                self.session.close()
                print("Oturum kapatıldı")
        except:
            pass


def main():
    """Ana fonksiyon"""
    card_manager = KAMUSMCardManagerV2()

    # Örnek e-Arşiv XML verisi
    sample_xml = '''<?xml version='1.0' encoding='UTF-8'?>
<earsiv:eArsivRaporu xmlns:earsiv="http://earsiv.efatura.gov.tr">
  <earsiv:baslik>
    <earsiv:versiyon>1.0</earsiv:versiyon>
    <earsiv:mukellef>
      <earsiv:vkn>9999999999</earsiv:vkn>
    </earsiv:mukellef>
    <earsiv:hazirlayan>
      <earsiv:vkn>9999999999</earsiv:vkn>
    </earsiv:hazirlayan>
    <earsiv:raporNo>FDB91815-AC02-4684-9AFB-488A742056B3</earsiv:raporNo>
    <earsiv:donemBaslangicTarihi>2025-09-21</earsiv:donemBaslangicTarihi>
    <earsiv:donemBitisTarihi>2025-09-21</earsiv:donemBitisTarihi>
    <earsiv:bolumBaslangicTarihi>2025-09-21</earsiv:bolumBaslangicTarihi>
    <earsiv:bolumBitisTarihi>2025-09-21</earsiv:bolumBitisTarihi>
    <earsiv:bolumNo>1</earsiv:bolumNo>
  </earsiv:baslik>
  <earsiv:ymRaporAylik>
    <earsiv:ymRaporNo>81631C87-7F30-4E13-A86C-7F0F1E5D88F6</earsiv:ymRaporNo>
    <earsiv:mukellef>
      <earsiv:vknTckn>9999999999</earsiv:vknTckn>
      <earsiv:unvan>DENEME AŞ</earsiv:unvan>
    </earsiv:mukellef>
    <earsiv:okc>
      <earsiv:marka>Newland</earsiv:marka>
      <earsiv:model>Paygo</earsiv:model>
      <earsiv:sicilNo>GIB12345678</earsiv:sicilNo>
    </earsiv:okc>
    <earsiv:okcAylikSatisRaporNo>93</earsiv:okcAylikSatisRaporNo>
    <earsiv:satis>
      <earsiv:vergiAdi>KDV</earsiv:vergiAdi>
      <earsiv:vergiTutar>22985.33</earsiv:vergiTutar>
      <earsiv:vergiDetay>
        <earsiv:vergiYuzde>20.0</earsiv:vergiYuzde>
        <earsiv:satisTutar>83002.58</earsiv:satisTutar>
      </earsiv:vergiDetay>
      <earsiv:vergiDetay>
        <earsiv:vergiYuzde>10.0</earsiv:vergiYuzde>
        <earsiv:satisTutar>19154.44</earsiv:satisTutar>
      </earsiv:vergiDetay>
      <earsiv:vergiDetay>
        <earsiv:vergiYuzde>1.0</earsiv:vergiYuzde>
        <earsiv:satisTutar>25539.25</earsiv:satisTutar>
      </earsiv:vergiDetay>
    </earsiv:satis>
    <earsiv:belgeTutar>
      <earsiv:tutar>127696.27</earsiv:tutar>
      <earsiv:tip>OKCFISTUTAR</earsiv:tip>
    </earsiv:belgeTutar>
    <earsiv:belgeTutar>
      <earsiv:tutar>127696.27</earsiv:tutar>
      <earsiv:tip>FATURATUTAR</earsiv:tip>
    </earsiv:belgeTutar>
    <earsiv:odemeTuruTutar>
      <earsiv:tutar>44693.69</earsiv:tutar>
      <earsiv:tip>NAKITODEME</earsiv:tip>
    </earsiv:odemeTuruTutar>
    <earsiv:odemeTuruTutar>
      <earsiv:tutar>70232.95</earsiv:tutar>
      <earsiv:tip>BKKARTODEME</earsiv:tip>
    </earsiv:odemeTuruTutar>
    <earsiv:bilgiFis>
      <earsiv:tutar>127696.27</earsiv:tutar>
      <earsiv:adet>152</earsiv:adet>
      <earsiv:tip>FATURABFIS</earsiv:tip>
    </earsiv:bilgiFis>
  </earsiv:ymRaporAylik>
</earsiv:eArsivRaporu>'''

    try:
        print("=== KAMUSM E-İmza Kartı XML İmzalama (python-pkcs11) ===\n")

        # PIN'i kullanıcıdan al
        pin = input("PIN kodunuzu girin (boş bırakabilirsiniz): ").strip()
        if not pin:
            pin = None

        # Kartı başlat
        if not card_manager.initialize_card(pin=pin):
            print("Kart başlatılamadı!")
            return

        # Sertifikaları listele
        certificates = card_manager.list_certificates()

        # Özel anahtarları listele
        private_keys = card_manager.list_private_keys()

        # XML imzalama işlemi
        if certificates and private_keys:
            print(f"\n=== E-Arşiv XML Belgesi İmzalama ===")
            print(f"Sertifika sayısı: {len(certificates)}")
            print(f"Özel anahtar sayısı: {len(private_keys)}")

            # XML'i imzala
            signed_xml = card_manager.sign_xml_document(sample_xml)

            if signed_xml:
                # İmzalanmış XML'i dosyaya kaydet
                saved_file = card_manager.save_signed_xml(signed_xml)

                if saved_file:
                    print(f"\n=== İmzalanmış XML Dosyası: {saved_file} ===")

                    # İmzalanmış XML'in ilk birkaç satırını göster
                    print(f"\n=== İmzalanmış XML Önizleme ===")
                    lines = signed_xml.split('\n')
                    for i, line in enumerate(lines[:15]):
                        print(f"{i + 1:2d}: {line}")
                    print("...")
                    print(f"Toplam {len(lines)} satır")
        elif not certificates:
            print("Sertifika bulunamadı!")
        elif not private_keys:
            print("Özel anahtar bulunamadı!")
        else:
            print("Sertifika veya özel anahtar bulunamadı!")

    except KeyboardInterrupt:
        print("\nUygulama kullanıcı tarafından durduruldu.")
    except Exception as e:
        print(f"Genel hata: {e}")
        import traceback
        traceback.print_exc()
    finally:
        card_manager.close()


if __name__ == "__main__":
    main()