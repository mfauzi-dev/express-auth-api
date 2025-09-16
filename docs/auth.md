# User API Spec

# Authentication

Endpoint ini digunakan untuk proses autentikasi pengguna, mulai dari pendaftaran akun, login, hingga manajemen sesi.  
Beberapa endpoint dapat diakses tanpa login (misalnya register, login, verifikasi email, lupa password), namun sebagian besar **akan menghasilkan JWT token** yang disimpan di **HTTP-only Cookie** setelah login.

## Fitur Utama

-   **Register** — Mendaftarkan akun baru
-   **Login** — Mengautentikasi pengguna dan membuat session
-   **Logout** — Menghapus session dan JWT token dari cookie
-   **Email Verification** — Memverifikasi email pengguna baru
-   **Forgot Password** — Mengirimkan tautan reset password ke email pengguna
-   **Reset Password** — Mengatur ulang password melalui tautan yang dikirim ke email

## Register User API

Endpoint : POST /api/auth/register

Request Body :

```json
{
    "name": "Test User",
    "email": "test@gmail.com",
    "password": "rahasia",
    "confirmPassword": "rahasia"
}
```

Success Response (201):

```json
{
    "success": true,
    "message": "User created successfully",
    "result": {
        "id": 1,
        "name": "Test User",
        "email": "test@gmail.com",
        "isVerified": false,
        "verificationToken": "123456",
        "verificationTokenExpiresAt": "2025-08-12T12:00:00.000Z",
        "createdAt": "2025-08-12T12:00:00.000Z",
        "updatedAt": "2025-08-12T12:00:00.000Z"
    }
}
```

Error Response (400):

```json
{
    "success": false,
    "message": "Password and confirm password do not match"
}
```

## Verify Email

Endpoint : POST /api/auth/verify-email

Request Body :

```json
{
    "code": "123456"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Email verified successfully",
    "user": {
        "id": 1,
        "name": "Test User",
        "email": "test@gmail.com",
        "isVerified": true
    }
}
```

Error Response (400):

```json
{
    "success": false,
    "message": "Invalid or expired verification code"
}
```

## Login

Endpoint : POST /api/auth/login

Request Body :

```json
{
    "email": "test@gmail.com",
    "password": "rahasia"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Email verified successfully",
    "user": {
        "id": 1,
        "name": "Test User",
        "email": "test@gmail.com",
        "isVerified": true
    }
}
```

Error Response (400):

```json
{
    "success": false,
    "message": "Invalid Credentials"
}
```

## Logout

Endpoint : POST /api/auth/logout

Success Response (200):

```json
{
    "success": true,
    "message": "Logged out successfully"
}
```

## Forgot Password

Endpoint : POST /api/auth/forgot-password

Request Body :

```json
{
    "email": "test@gmail.com"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Password reset link sent to your email"
}
```

Error Response (400):

```json
{
    "success": false,
    "message": "User not found"
}
```

## Reset Password

Endpoint : POST /api/auth/reset-password/:token

Request Body :

```json
{
    "password": "rahasia2"
}
```

Success Response (200):

```json
{
    "success": true,
    "message": "Password reset success"
}
```

## Check Auth

Endpoint : POST /api/auth/check-auth

Success Response (200):

```json
{
    "success": true,
    "user": {
        "id": "1",
        "name": "Test User",
        "email": "test@gmail.com"
    }
}
```
