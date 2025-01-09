# SSO OTP Sumut - Aplikasi Otentikasi SSO

Aplikasi otentikasi untuk SSO (Single Sign-On) yang digunakan oleh BPS Provinsi Sumatera Utara. Proyek ini mengintegrasikan otentikasi berbasis JWT yang menggunakan enkripsi AES-256 dan token aplikasi untuk memastikan otentikasi yang aman dan valid.

## Prasyarat

Pastikan kamu sudah menginstal dan menyiapkan software berikut:

- [PHP](versi 7.4 atau lebih baru)
- [composer]
- [Yii2]
- [firebase/php-jwt]- Untuk membuat dan memverifikasi token JWT

## Instalasi

Langkah-langkah untuk menyiapkan dan menjalankan proyek secara lokal.

### 1. Clone repository

Clone repository proyek ini ke lokal dengan perintah berikut:

```bash
git clone <repository-url>
```

### 2. Masuk ke direktori proyek

Masuk ke dalam direktori proyek yang sudah di-clone:

```bash
cd <nama-direktori>
```

### 3. Instal dependensi

Instal semua dependensi yang dibutuhkan menggunakan npm:

```bash
composer require firebase/php-jwt --ignore-platform-reqs
```
lalu install vendornya
```bash
composer require sso_otp_sumut/jwt-authentication:dev-main --ignore-platform-reqs

```
### 4. Pada file params.php

file `params.php` di direktori root proyek (biasanya di config). Salin dan sesuaikan konfigurasi berikut:

```bash
return [
    'encryptionKey' => 'your_32_bytes_encryption_key_here',
    'secretKey' => 'your_secret_key_here',
    'appToken' => 'your_app_token_here',
    'ssoLoginURL' => 'your_sso_login_url_here',
];
```

Penjelasan variabel .env:

- encryptionKey: Kunci enkripsi 32 byte untuk mendekripsi data.

- secretKey: Kunci rahasia untuk menandatangani dan memverifikasi JWT.

- appToken: Token aplikasi yang digunakan untuk memverifikasi aplikasi pada sistem.

- ssoLoginURL: URL untuk halaman login SSO yang digunakan untuk otentikasi pengguna.

### 4. Pada file web.php

file `web.php` di direktori root proyek (biasanya di config). Salin dan sesuaikan konfigurasi berikut:

```bash
'components' => [
        'request' => [
            'enableCookieValidation' => false, // ini di ubah jika true jika tidak ada tambahkan
            // !!! insert a secret key in the following (if it is empty) - this is required by cookie validation
            'cookieValidationKey' => '9N95r8jb44okwDNpl6QJ3YUy0vsf9e8M',
        ],
,'as beforeRequest' => [
    'class' => 'yii\filters\AccessControl',
    'rules' => [
        [
            'allow' => true,
            'actions' => ['index'], // Hanya izinkan akses ke halaman index tanpa login
        ],
        [
            'allow' => true,
            'roles' => ['@'],
        ],
    ]]]
```
tambahkan di composer.json:
```php
"autoload": {
    "psr-4": {
      "sso_otp_sumut\\jwtauthentication\\": "vendor/sso_otp_sumut/jwt-authentication/src/"
    }
  }
```
jangan lupa dump autoload dengan 
```bash
composer dump-autoload
```

### Struktur Proyek

Berikut adalah struktur proyek secara keseluruhan:

- **/config/params.php**
- **/config/web.php**
- **/controller/siteController.php**
- **vendor\sso_otp_sumut\jwt-authentication\src\JWTAuthenticator.php**

## Penggunaan

### 1. Akses SSOnya

Jika token JWT tidak ada atau tidak valid, pengguna akan diarahkan ke halaman login SSO yang ditentukan dalam variabel `LINK_SSO`. buat function `beforeAction` sebelum mengakses ke `action index` pada siteController untuk authentikasinya. contoh aplikasi penggunaan di bawah ini

```php
use sso_otp_sumut\jwtauthentication\JWTAuthenticator;

 public function beforeAction($action)
    {
        // Panggil komponen JWTAuthenticator untuk memverifikasi token sebelum aksi dijalankan
        $authenticator = new JWTAuthenticator(); //ini yang dipanggil dari vendor nanti
        $authResult = $authenticator->authenticate();

        // Jika hasilnya berupa redirect, maka proses ini akan menghentikan eksekusi dan redirect.
        if ($authResult) {
            return $authResult;
        }

    
        return parent::beforeAction($action);
    }
    
    /**
     * Displays homepage.
     *
     * @return string
     */
    public function actionIndex()
    {
        if (Yii::$app->user->isGuest) {
            return Yii::$app->response->redirect(Yii::$app->params['ssoLoginURL']);
        }
        $model = Satker::find()->all();
        $sql = "SELECT c.kode_satker, e.nama as satker, d.formasi, d.eligible, c.pegawai, (d.eligible - c.pegawai) kurang FROM (SELECT a.kode_satker, count(a.nip_lama) pegawai FROM data_pegawai a WHERE a.aktif='y' GROUP BY a.kode_satker) c, (SELECT b.satker, sum(b.formasi) formasi, sum(eligible) eligible FROM formasi b GROUP BY satker) d, satker e WHERE c.kode_satker=d.satker AND c.kode_satker = e.kode ORDER BY c.kode_satker ASC";
        $rekapPegawai = Yii::$app->db->createCommand($sql)->queryAll();
        return $this->render('index');
        //return $this->redirect(['formasi/terisi']);
    }
```

### 2. Logout

Untuk logout, akses halaman `/logout` yang akan menghapus cookie JWT dan mengarahkan pengguna kembali ke halaman utama atau halaman login.

```php

 public $enableCsrfValidation = false;

/**
     * Logout action.
     *
     * @return Response
     */
    public function actionLogout()
    {

        
       // Mengatur waktu kedaluwarsa cookie JWT ke waktu yang sudah lewat
        Yii::$app->response->cookies->add(new \yii\web\Cookie([
            'name' => 'jwt',
            'value' => '',
            'domain' => 'bps.web.id',
            'expire' => time() - 3600, // Waktu kedaluwarsa sudah lewat
            'secure' => true,
            'httpOnly' => true,
            'sameSite' => 'None',
        ]));
        

        
        Yii::$app->user->logout();
        
        return Yii::$app->response->redirect(Yii::$app->params['ssoLoginURL']);

    }
```


## Troubleshooting

### 1. Error Cookie Tidak Tersimpan

Pastikan bahwa server menggunakan HTTPS dan cookie memiliki opsi `secure: true` agar dapat disimpan di browser.

### 2. Token Tidak Valid

Pastikan token yang diterima benar dan sesuai dengan format yang diharapkan. Token yang dienkripsi harus didekripsi terlebih dahulu sebelum diverifikasi.

### 3. Browser Cache

Jika ada perubahan pada cookie atau token, pastikan untuk membersihkan cache browser untuk memastikan data yang terbaru digunakan.

## Kontribusi

Jika kamu ingin berkontribusi pada proyek ini, silakan fork repository ini dan kirimkan pull request. Pastikan untuk melakukan pengujian yang memadai sebelum mengirimkan kontribusimu.

## Lisensi

Proyek ini dilisensikan di bawah [MIT License](https://opensource.org/licenses/MIT).
