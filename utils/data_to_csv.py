import csv
import random

# CSV dosyası oluşturma
def stok_listesi_olustur():
    # Kırtasiye ürünleri listesi
    urunler = [
        "Kalem",
        "Defter", 
        "Silgi",
        "Cetvel",
        "Makas",
        "Yapıştırıcı",
        "Kalemtraş",
        "Dosya",
        "Klasör",
        "Zımba",
        "Post-it",
        "Marker",
        "Renkli Kalem",
        "Hesap Makinesi",
        "Pergel",
        "Gönye",
        "Stapler Teli",
        "Bant",
        "Karton",
        "Fotokopi Kağıdı"
    ]
    
    # CSV dosyası oluşturma
    with open('stok_listesi.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Başlıkları yazma
        writer.writerow(['urun_id', 'urun_adi', 'stok_miktari', 'kritik_seviye'])
        
        # Ürün verilerini yazma
        for i, urun in enumerate(urunler, 1):
            # Rastgele ama mantıklı stok ve kritik seviye değerleri
            stok_miktari = random.randint(1, 50)
            kritik_seviye = random.randint(3, min(15, stok_miktari))
            
            writer.writerow([i, urun, stok_miktari, kritik_seviye])
    
    print("CSV dosyası başarıyla oluşturuldu")

# Fonksiyonu çalıştırma
if __name__ == "__main__":
    stok_listesi_olustur()
