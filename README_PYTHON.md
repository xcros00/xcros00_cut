# NetCut (Python Edition) ✂

Implementasi ulang lengkap dari perkakas **NetCut-cli (C++)** ke dalam bahasa **Python**. Tool ini digunakan untuk memindai perangkat di jaringan lokal (LAN/Wi-Fi) dan memutus/memulihkan koneksi internet target menggunakan teknik **ARP Spoofing**.

---

## Fitur Utama

1. **Dual Antarmuka**:
   - **Interactive CLI (`main.py` / `ptes.py`)**: Tampilan terminal berwarna (hijau untuk target aktif, merah untuk target yang dipotong).
   - **Modern Web Dashboard (`web_app.py`)**: Antarmuka web responsif berbasis Flask dengan status realtime dan kontrol klik.
2. **Mesin Pemindai Cepat**:
   - Pemindaian Layer 2 Scapy (`srp(Ether/ARP)`).
   - Multi-threaded Windows `SendARP` API fallback (dapat menemukan IP & MAC host di Windows tanpa driver pihak ketiga).
   - Deteksi otomatis interface aktif dan default gateway.
3. **Pemberhentian & Pemulihan Aman**:
   - Saat keluar dengan menekan `q` atau `Ctrl+C`, sistem otomatis mengirimkan paket ARP asli untuk memulihkan koneksi seluruh target ke kondisi normal.

---

## Kebutuhan Sistem

- **Python**: 3.9+
- Pustaka Python:
  ```bash
  pip install -r requirements.txt
  ```

### Catatan Platform:
- **Linux**: Jalankan dengan `sudo` karena crafting raw packet ARP memerlukan privilege root:
  ```bash
  sudo python main.py
  ```
- **Windows**: 
  - Pemindaian perangkat (scanning) berjalan langsung tanpa konfigurasi tambahan.
  - Untuk mengirimkan raw packet ARP spoofing di Windows, pastikan driver **Npcap** telah terinstal (dapat diunduh dari [npcap.com](https://npcap.com) dengan opsi *"Install Npcap in WinPcap API-compatible Mode"* diaktifkan).

---

## Cara Penggunaan

### 1. Mode Terminal Interaktif (CLI)

Jalankan perintah:
```bash
python main.py
# atau
python ptes.py
```

Opsi argumen:
```bash
python main.py -i 3.0    # Mengatur interval spoofing ke 3 detik (default: 2.0 detik)
```

**Kontrol pada CLI:**
- Masukkan nomor target (misal: `1` atau `2 4 5`) untuk memutus koneksi (CUT).
- Masukkan nomor target yang sudah berstatus merah lagi untuk memulihkan koneksinya (RECOVER).
- Ketik `r` untuk memindai ulang perangkat jaringan.
- Ketik `q` untuk memulihkan seluruh koneksi target dan keluar secara aman.

---

### 2. Mode Web Dashboard (Browser)

Jalankan server web:
```bash
python web_app.py
```

Buka browser dan akses:
```
http://127.0.0.1:5000
```

Fitur Web:
- Tombol **Scan Network** untuk memindai perangkat secara langsung.
- Tombol **Cut** / **Recover** di setiap baris perangkat.
- Tombol **Recover All** untuk memulihkan seluruh perangkat sekaligus.
- Pembaruan status realtime setiap 5 detik.
