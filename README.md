# alys — Alysis Code Key Harvester

CLI tool otomatis untuk harvesting API key (`slk_...`) dari Alysis Code via Supabase auth dan device code grant flow.

---

## 📁 Struktur File

```
alys/
├── alys.py              # Harvester engine & CLI runner
├── config.json          # Konfigurasi aktif (9router & tmpmail)
├── config.example.json  # Template konfigurasi 9router & tmpmail
├── akun.txt             # File credentials akun (email:password)
├── akun.example.txt     # Contoh format daftar akun
├── requirements.txt     # Daftar dependensi Python
├── keys.txt             # Output dump hasil minting key (auto-generated, chmod 0600)
└── state/
    └── harvest.json     # State lokal penyimpanan token & key (chmod 0600)
```

---

## ⚡ Instalasi

Harvester utama berjalan menggunakan standard library Python 3.10+:

```bash
# Optional: jika menggunakan fitur Google OAuth login (glogin)
pip install -r requirements.txt
python3 -m camoufox fetch
```

---

## ⚙️ Konfigurasi (`config.json`)

Tool ini membaca file `config.json` di direktori kerja untuk integrasi 9router dan tmpmail worker.

```json
{
  "9router": {
    "dashboard_url": "https://9router.example.com",
    "password": "YOUR_DASHBOARD_PASSWORD",
    "base_url": "https://9router.example.com/v1",
    "api_key": "sk_9router_key",
    "provider_id": "openai-compatible-chat-...",
    "node_prefix": "ali",
    "model_prefix": "ali",
    "auto_push": true
  },
  "tmpmail": {
    "url": "https://tmpmail.example.workers.dev",
    "token": "YOUR_TMPMAIL_WORKER_TOKEN",
    "domain": "mail.example.com",
    "user_agent": "tmpmail-client/1.0",
    "poll_interval": 5,
    "timeout": 120
  }
}
```

Cek konfigurasi aktif dengan:
```bash
python3 alys.py config
```

---

## 📋 Format `akun.txt`

Satu akun per baris. Baris kosong dan komentar `#` otomatis diabaikan. Separator yang didukung: `:`, `|`, `;`, `,`, atau `TAB`.

```txt
user1@domain.com:Password123!
user2@domain.com|Password456!
user3@domain.com;Password789!
user4@domain.com    PasswordABC!
user5@domain.com     # Tanpa password -> memakai refresh_token atau password di state
```

---

## 🚀 Penggunaan CLI

### 0. Mode Interaktif / Menu CLI (`menu`)
Cukup jalankan script tanpa argumen atau dengan perintah `menu` untuk membuka antarmuka menu interaktif berbasis teks:

```bash
# Cara paling cepat dan mudah:
python3 alys.py

# Atau eksplisit:
python3 alys.py menu
```

Fitur di menu interaktif mencakup:
- [1] Import Akun dari file ke state
- [2] Batch harvesting dengan opsi jumlah worker dan key
- [3] Single harvest untuk satu akun
- [4] Cek status semua akun dan token tersimpan
- [5] Cek status konfigurasi 9router & tmpmail
- [6] Test validitas key langsung ke endpoint `/models` & `/chat/completions`
- [7] Google OAuth Login (Otomatis Headless via Camoufox untuk akun Google / manual)
- [8] Sync ke 9router (Daftarkan seluruh key slk_ ke 9router provider pool)
### 1. Import Akun ke State (`import`)
Mengimpor kredensial dari `akun.txt` langsung ke `state/harvest.json`. Kredensial akan tersimpan rapi untuk digunakan berulang kali tanpa harus mengetik password lagi:

```bash
# Default membaca akun.txt (atau accounts.txt)
python3 alys.py import

# Menentukan file kustom
python3 alys.py import --file /path/ke/daftar_akun.txt
```

### 2. Batch Harvesting (`batch`)
Menjalankan multi-threading minting key secara paralel untuk seluruh akun:

```bash
# Otomatis membaca akun.txt (atau fallback ke akun yang ada di state jika file tidak ada)
python3 alys.py batch --workers 4 --count 2

# Menggunakan kredensial yang sudah tersimpan di state (tanpa perlu file)
python3 alys.py batch --stored --workers 4 --count 1

# Menyimpan dump hasil semua key ke file spesifik (default keys.txt)
python3 alys.py batch --file akun.txt --out keys.txt
```

### 3. Single Account Harvest (`harvest`)
Minting key untuk satu akun tertentu:

```bash
# Jika password sudah ada di state/akun.txt, parameter --password bersifat opsional
python3 alys.py harvest --email user1@domain.com --count 2

# Menjalankan dengan password manual
python3 alys.py harvest --email user1@domain.com --password 'Password123!' --count 2
```

### 4. Google OAuth Login (`glogin`)
Jika akun login menggunakan Google OAuth (misalnya domain Google Workspace seperti `@paragadis.com` atau `@gmail.com`), gunakan `glogin`:

```bash
# Batch otomatis semua akun di akun.txt via Camoufox headless
python3 alys.py glogin --batch --count 1
# Login 1 akun Google dengan email dan password otomatis
python3 alys.py glogin --email user@example.com --password 'Password123!' --count 1

# Login manual browser window (Jack personal Google consent)
python3 alys.py glogin --count 1
```

Setelah login Google OAuth berhasil sekali, `refresh_token` otomatis tersimpan di `state/harvest.json`. Semua proses harvest berikutnya langsung menggunakan token refresh tanpa perlu browser lagi.

### 5. Cek Status & Key (`status`)
Melihat ringkasan akun, token yang tersimpan, dan daftar key `slk_`:

```bash
python3 alys.py status
```

### 6. Test Model & Gateway Probe (`models` & `chat`)
Memverifikasi validitas key `slk_` langsung ke endpoint gateway:

```bash
# Cek model yang tersedia
python3 alys.py models --key slk_xxxxxxxxxxxxxxxxxxxx

# Tes chat completion
python3 alys.py chat --key slk_xxxxxxxxxxxxxxxxxxxx --model deepseek-v4-flash --prompt "Halo"
```

### 7. Sync ke 9router (`sync-9router`)
Mendaftarkan seluruh API key `slk_` yang tersimpan di `state/harvest.json` ke 9router provider node:

```bash
python3 alys.py sync-9router
```

> Catatan: Setiap kali key diminting (`harvest` / `glogin`), key tersebut **otomatis didaftarkan ke 9router** jika `"auto_push": true` di `config.json`. Perintah `sync-9router` berguna jika ingin memastikan semua key lama atau yang belum terdaftar ikut disinkronkan.

### 8. Routing via 9router
Setelah key masuk ke 9router, request API OpenAI-compatible dapat diarahkan ke 9router dengan prefix model `ali`:

```bash
curl -X POST https://9router.example.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_your_9router_key" \
  -d '{
    "model": "ali/deepseek-v4-flash",
    "messages": [{"role": "user", "content": "Halo Alysis via 9router"}],
    "max_tokens": 50
  }'
```
---

## 🔒 Keamanan Data

- File `state/harvest.json` dan file output `keys.txt` otomatis diset dengan permission restricted `chmod 0600` (hanya user pemilik yang dapat membaca dan menulis).
- Password dan token hanya disimpan di file state lokal Anda.
