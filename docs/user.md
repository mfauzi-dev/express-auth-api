# User

Endpoint ini digunakan untuk mengelola data pengguna yang sudah terautentikasi.  
Semua endpoint di bagian ini **memerlukan login** dan akan memverifikasi JWT token yang tersimpan di HTTP-only Cookie.

## Fitur Utama

-   **Update Password** — Mengubah kata sandi pengguna yang sedang login
-   **Update Profile** — Mengubah data profil
-   **Get User Profile** — Mengambil data profil pengguna yang sedang login

## Update Password

Endpoint : POST /api/password

Request Body :

```json
{
    "oldPassword": "rahasia",
    "newPassword": "123456",
    "confirmPassword": "123456"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Password updated successfully"
}
```

## Update Profile

Endpoint : POST /api/profile

Request Body :

```json
{
    "name": "Test User Update"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

## Get User Profile

Endpoint : POST /api/profile

Request Body :

```json
{
    "name": "Test User Update"
}
```

Success Response (200):

```json
{
    "success": true,
    "user": {
        "id": 1,
        "name": "Test User Update",
        "email": "test@example.com",
        "isVerified": true
    }
}
```
