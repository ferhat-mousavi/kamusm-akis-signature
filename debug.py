#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAMUSM E-İmza Kartı Debug ve Test Aracı
Gerekli kütüphaneler: pip install PyKCS11 cryptography python-pkcs11
"""

import os
import sys
import ctypes
from ctypes import wintypes
import platform


def check_system_info():
    """Sistem bilgilerini kontrol et"""
    print("=== Sistem Bilgileri ===")
    print(f"Python versiyon: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Architecture: {platform.architecture()}")
    print(f"İşlemci: {platform.processor()}")
    print()


def check_dll_dependencies():
    """DLL bağımlılıklarını kontrol et"""
    print("=== DLL Bağımlılıkları Kontrolü ===")
    lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

    if not os.path.exists(lib_path):
        print(f"HATA: {lib_path} bulunamadı!")
        return False

    print(f"DLL dosyası bulundu: {lib_path}")
    print(f"Dosya boyutu: {os.path.getsize(lib_path)} byte")

    try:
        # DLL'i doğrudan yükle
        dll = ctypes.windll.LoadLibrary(lib_path)
        print("✓ DLL başarıyla yüklendi (ctypes)")

        # PKCS#11 fonksiyonlarının varlığını kontrol et
        required_functions = [
            'C_Initialize', 'C_Finalize', 'C_GetInfo',
            'C_GetSlotList', 'C_GetTokenInfo', 'C_OpenSession'
        ]

        missing_functions = []
        for func_name in required_functions:
            try:
                getattr(dll, func_name)
                print(f"✓ {func_name} fonksiyonu mevcut")
            except AttributeError:
                missing_functions.append(func_name)
                print(f"✗ {func_name} fonksiyonu bulunamadı")

        if missing_functions:
            print(f"Eksik fonksiyonlar: {missing_functions}")
            return False

        return True

    except Exception as e:
        print(f"✗ DLL yükleme hatası: {e}")
        return False


def test_with_raw_ctypes():
    """Ham ctypes ile PKCS#11 test et"""
    print("\n=== Ham CTypes ile PKCS#11 Testi ===")
    lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

    try:
        # DLL'i yükle
        pkcs11 = ctypes.windll.LoadLibrary(lib_path)

        # C_Initialize çağır
        print("C_Initialize çağrılıyor...")
        result = pkcs11.C_Initialize(None)
        print(f"C_Initialize sonucu: 0x{result:08x}")

        if result != 0 and result != 0x191:  # CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
            print(f"C_Initialize hatası: 0x{result:08x}")
            return False

        # Slot sayısını al
        slot_count = ctypes.c_ulong(0)
        result = pkcs11.C_GetSlotList(0, None, ctypes.byref(slot_count))
        print(f"C_GetSlotList sonucu: 0x{result:08x}")
        print(f"Toplam slot sayısı: {slot_count.value}")

        if slot_count.value > 0:
            # Slotları al
            slots = (ctypes.c_ulong * slot_count.value)()
            result = pkcs11.C_GetSlotList(0, slots, ctypes.byref(slot_count))
            print(f"Slot listesi alındı, sonuç: 0x{result:08x}")

            for i in range(slot_count.value):
                print(f"Slot {i}: {slots[i]}")

        # Temizle
        pkcs11.C_Finalize(None)
        print("✓ Ham ctypes testi başarılı")
        return True

    except Exception as e:
        print(f"✗ Ham ctypes testi hatası: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_with_python_pkcs11():
    """python-pkcs11 kütüphanesi ile test et"""
    print("\n=== python-pkcs11 Kütüphanesi ile Test ===")

    try:
        import pkcs11
        lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

        # Kütüphaneyi yükle
        lib = pkcs11.lib(lib_path)
        print("✓ python-pkcs11 ile kütüphane yüklendi")

        # Slotları listele
        slots = lib.get_slots()
        print(f"Bulunan slot sayısı: {len(slots)}")

        for i, slot in enumerate(slots):
            print(f"Slot {i}: {slot}")
            try:
                token = slot.get_token()
                print(f"  Token: {token}")
                print(f"  Token mevcut: {token.token_present}")
                print(f"  Token etiketi: {token.label}")
            except Exception as token_error:
                print(f"  Token bilgisi alınamadı: {token_error}")

        print("✓ python-pkcs11 testi başarılı")
        return True

    except ImportError:
        print("python-pkcs11 kütüphanesi yüklü değil")
        print("Yüklemek için: pip install python-pkcs11")
        return False
    except Exception as e:
        print(f"✗ python-pkcs11 testi hatası: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_with_pykcs11():
    """PyKCS11 ile farklı yaklaşımlar dene"""
    print("\n=== PyKCS11 ile Farklı Yaklaşımlar ===")

    try:
        import PyKCS11
        lib_path = os.path.join(os.path.dirname(__file__), "akis_lib", "akisp11.dll")

        # Yaklaşım 1: Normal yükleme
        try:
            print("Yaklaşım 1: Normal PyKCS11 yükleme...")
            pkcs11_lib = PyKCS11.PyKCS11Lib()
            pkcs11_lib.load(lib_path)
            print("✓ Normal yükleme başarılı")

            slots = pkcs11_lib.getSlotList()
            print(f"Slot sayısı: {len(slots)}")
            return True

        except Exception as e1:
            print(f"✗ Normal yükleme hatası: {e1}")

        # Yaklaşım 2: Manuel initialize
        try:
            print("Yaklaşım 2: Manuel initialize...")
            pkcs11_lib = PyKCS11.PyKCS11Lib()

            # DLL'i manuel yükle
            import ctypes
            dll = ctypes.windll.LoadLibrary(lib_path)

            # PyKCS11'e manuel olarak ata
            pkcs11_lib.lib = dll

            # Initialize et
            result = dll.C_Initialize(None)
            print(f"Manual C_Initialize sonucu: 0x{result:08x}")

            if result == 0 or result == 0x191:
                print("✓ Manuel initialize başarılı")
                return True
            else:
                print(f"✗ Manuel initialize hatası: 0x{result:08x}")

        except Exception as e2:
            print(f"✗ Manuel initialize hatası: {e2}")

        return False

    except ImportError:
        print("PyKCS11 kütüphanesi yüklü değil")
        return False
    except Exception as e:
        print(f"✗ PyKCS11 genel hatası: {e}")
        return False


def check_smart_card_service():
    """Windows Smart Card servisini kontrol et"""
    print("\n=== Windows Smart Card Servisi Kontrolü ===")

    try:
        import subprocess

        # Smart Card servis durumunu kontrol et
        result = subprocess.run(['sc', 'query', 'SCardSvr'],
                                capture_output=True, text=True)

        if result.returncode == 0:
            if "RUNNING" in result.stdout:
                print("✓ Smart Card servisi çalışıyor")
            else:
                print("✗ Smart Card servisi çalışmıyor")
                print("Başlatmak için: sc start SCardSvr")
        else:
            print("Smart Card servis durumu kontrol edilemedi")

        # PC/SC servisi kontrol et
        result = subprocess.run(['sc', 'query', 'SCManager'],
                                capture_output=True, text=True)

        print(f"SC Manager durumu: {result.returncode}")

    except Exception as e:
        print(f"Servis kontrol hatası: {e}")


def main():
    """Ana debug fonksiyonu"""
    print("KAMUSM E-İmza Kartı Debug Aracı")
    print("=" * 50)

    # Sistem bilgilerini kontrol et
    check_system_info()

    # Smart Card servisini kontrol et
    check_smart_card_service()

    # DLL bağımlılıklarını kontrol et
    dll_ok = check_dll_dependencies()

    if dll_ok:
        # Farklı yöntemlerle test et
        ctypes_ok = test_with_raw_ctypes()
        python_pkcs11_ok = test_with_python_pkcs11()
        pykcs11_ok = test_with_pykcs11()

        print("\n=== Test Sonuçları ===")
        print(f"DLL Yükleme: {'✓' if dll_ok else '✗'}")
        print(f"Ham CTypes: {'✓' if ctypes_ok else '✗'}")
        print(f"python-pkcs11: {'✓' if python_pkcs11_ok else '✗'}")
        print(f"PyKCS11: {'✓' if pykcs11_ok else '✗'}")

        if ctypes_ok and not pykcs11_ok:
            print("\nÖNERİ: Ham ctypes çalışıyor ama PyKCS11 çalışmıyor.")
            print("python-pkcs11 kütüphanesini deneyin: pip install python-pkcs11")

    else:
        print("\n✗ DLL yüklenemediği için diğer testler yapılamadı")
        print("KAMUSM sürücülerinin doğru yüklendiğinden emin olun")


if __name__ == "__main__":
    main()