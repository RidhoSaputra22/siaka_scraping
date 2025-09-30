# Implementasi Route `/api/login` - SISKA Scraping API

## Ringkasan Perubahan

Telah berhasil ditambahkan route baru `/api/login` pada Flask API yang berfungsi untuk memverifikasi kredensial login ke sistem SISKA UNDIPA tanpa mengambil data jadwal.

## Endpoint Baru

### POST `/api/login`

**Deskripsi:** Endpoint untuk verifikasi kredensial login ke SISKA

**Method:** POST

**Content-Type:** application/json

**Rate Limit:** 5 requests per minute (sama dengan endpoint lainnya)

### Request Format

```json
{
  "username": "your_username", // required, 3-50 karakter
  "password": "your_password", // required, 6-100 karakter
  "level": "mahasiswa" // optional: mahasiswa|dosen|admin|staf
}
```

### Response Format

#### Success Response (200)

```json
{
    "status": "success",
    "message": "Login credentials verified successfully",
    "timestamp": "2025-09-30T12:00:00Z",
    "data": {
        "login_status": "authenticated",
        "level": "mahasiswa",
        "metadata": {
            "verified_at": "2025-09-30T12:00:00Z",
            "session_id": "abc12345",
            "rate_stats": {...},
            "ssl_status": {
                "ssl_verified": true,
                "warning": null
            },
            "encoding": "UTF-8"
        }
    }
}
```

#### Error Response (401 - Login Failed)

```json
{
  "status": "error",
  "message": "Authentication failed",
  "timestamp": "2025-09-30T12:00:00Z",
  "error_code": "LOGIN_FAILED"
}
```

#### Error Response (400 - Validation Error)

```json
{
  "status": "error",
  "message": "Username must be 3-50 characters",
  "timestamp": "2025-09-30T12:00:00Z",
  "error_code": "INVALID_USERNAME"
}
```

## Fitur Keamanan

1. **Input Validation:** Username dan password divalidasi format dan panjangnya
2. **Rate Limiting:** Maksimal 5 request per menit untuk mencegah brute force
3. **Security Logging:** Semua attempt login dicatat tanpa expose data sensitif
4. **SSL Handling:** Otomatis menangani masalah SSL certificate
5. **Unicode Support:** Mendukung karakter Unicode dengan proper encoding
6. **Error Sanitization:** Error message tidak expose detail sistem

## Perbedaan dengan `/api/jadwal`

| Aspek    | `/api/login`           | `/api/jadwal`        |
| -------- | ---------------------- | -------------------- |
| Fungsi   | Hanya verifikasi login | Login + ambil jadwal |
| Response | Status autentikasi     | Data jadwal lengkap  |
| Performa | Lebih cepat            | Lebih lambat         |
| Use Case | Validasi kredensial    | Ambil data jadwal    |

## Perubahan pada File

### 1. `app.py` - Penambahan Route

- Ditambah endpoint `/api/login` dengan handler `check_login()`
- Update dokumentasi API pada endpoint `/` dan `/api/docs`
- Implementasi validasi input yang sama seperti endpoint jadwal
- Penanganan error SSL dan Unicode yang konsisten

### 2. Struktur Code yang Ditambahkan

```python
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def check_login():
    # Validasi input
    # Inisialisasi scraper
    # Attempt login ke SISKA
    # Return status verifikasi
```

## Testing

Endpoint telah ditest dengan berbagai skenario:

1. ✅ Validasi Content-Type
2. ✅ Validasi format JSON
3. ✅ Validasi username (panjang, karakter)
4. ✅ Validasi password (panjang)
5. ✅ Rate limiting (5 req/menit)
6. ✅ SSL handling
7. ✅ Error logging
8. ✅ Response format

## Contoh Penggunaan

### Dengan curl:

```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_nim","password":"your_password","level":"mahasiswa"}'
```

### Dengan Python requests:

```python
import requests

url = "http://localhost:5000/api/login"
data = {
    "username": "your_nim",
    "password": "your_password",
    "level": "mahasiswa"
}

response = requests.post(url, json=data)
result = response.json()

if response.status_code == 200:
    print("Login berhasil!")
    print(f"Status: {result['data']['login_status']}")
else:
    print("Login gagal!")
    print(f"Error: {result['message']}")
```

## Kesimpulan

Route `/api/login` telah berhasil diimplementasikan dengan:

- Fitur keamanan yang lengkap
- Error handling yang robust
- Format response yang konsisten
- Dokumentasi API yang update
- Testing yang komprehensif

Endpoint ini siap digunakan untuk aplikasi mobile SIAKA untuk verifikasi login sebelum mengambil data jadwal.
