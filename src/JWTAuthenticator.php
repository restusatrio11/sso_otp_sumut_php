<?php
namespace app\components;

use Yii;
use yii\base\Component;
use yii\web\Cookie;
use app\models\User;

// Include library firebase/php-jwt secara manual
require_once Yii::getAlias('@app/vendor/firebase/php-jwt/src/JWT.php');
require_once Yii::getAlias('@app/vendor/firebase/php-jwt/src/Key.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;



class JWTAuthenticator extends Component
{
    // Deklarasi variabel untuk kunci enkripsi dan token aplikasi
    private $encryptionKey;
    private $secretKey;
    

    public function init()
    {
        parent::init();
        // Inisialisasi kunci rahasia dan enkripsi dari environment atau config
        $this->encryptionKey = Yii::$app->params['encryptionKey'];  // Anda bisa mendefinisikan kunci di config
        $this->secretKey = Yii::$app->params['secretKey'];          // Kunci untuk JWT
        
    }

   private function decryptJWT($encrypted)
    {
    
        // Konversi IV dan data terenkripsi dari hex ke binari
        $iv = hex2bin($encrypted['iv']);
        $data = hex2bin($encrypted['data']);
        
        
    
        
    
        // Dekripsi menggunakan AES-256-CBC
        $decrypted = openssl_decrypt($data, 'aes-256-cbc', $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
    
        // Periksa hasil dekripsi
        if ($decrypted === false) {
            error_log('Dekripsi gagal: ' . openssl_error_string());
            throw new \Exception("Dekripsi gagal. Pastikan kunci dan IV benar.");
        }
    
    
        return $decrypted;
    }



    // Fungsi untuk memverifikasi JWT
    public function authenticate()
    {
        $cookies = Yii::$app->request->cookies;
        $token = $cookies->getValue('jwt'); // Ambil token JWT dari cookie
        
        // Kirimkan cookie token aplikasi ke browser (mirip dengan res.cookie di Express)
        
        Yii::$app->response->cookies->add(new \yii\web\Cookie([
            'name' => 'tokenApp',
            'value' => Yii::$app->params['appToken'], // Nilai mentah, tidak di-hash atau di-serialize
            'httpOnly' => true,
            'secure' => true,
            'sameSite' => 'None',
            'domain' => 'bps.web.id',
            'expire' => time() + 3600,
        ]));

        $decodedToken = base64_decode(Yii::$app->params['appToken']); // Dekode base64
        if (empty($token)) {
            // Redirect ke login SSO jika token tidak ada atau kosong
            $redirectURL = urlencode($decodedToken);
            error_log('redirectURL: ' . $redirectURL);
            return Yii::$app->response->redirect(Yii::$app->params['ssoLoginURL'] . "?redirect=" . $redirectURL);
        }

        try {
            $encryptedToken = json_decode($token, true);
            
             // Pastikan data terenkripsi dan IV ada
                if (isset($encryptedToken['iv']) && isset($encryptedToken['data'])) {
                    $decryptedJWT = $this->decryptJWT($encryptedToken); // Dekripsi token
        
                    if ($decryptedJWT === false) {
                        throw new \Exception("Token gagal didekripsi.");
                    }
        
                    // Verifikasi JWT dengan kunci rahasia
                    $decoded = \Firebase\JWT\JWT::decode($decryptedJWT, new Key($this->secretKey, 'HS256'));
                    error_log('Isi decoded token JWT: ' . json_encode($decoded));
        
                    // Simpan data pengguna di Yii::$app->user atau di session
                    // Yii::$app->user->setIdentity($decoded);
                    
                    // Mengambil username dari decoded token
                    $username = $decoded->username;
                    $user = User::findOne(['username'=>$username]);
                    if($user){
                        Yii::$app->user->login($user);
                        //echo Yii::$app->user->identity->nip_lama;
                        // return $this->redirect(['index']);
                    }
        
                    // Verifikasi token aplikasi
                    if ($decoded->token !== Yii::$app->params['appToken']) {
                        throw new \Exception("Token aplikasi tidak valid.");
                    }
        
                } else {
                    throw new \Exception("Format token tidak valid.");
                }


            
        } catch (\Exception $e) {
            // Jika token tidak valid atau ada error, redirect ke halaman login SSO
            $redirectURL = urlencode($decodedToken);
            error_log('redirectURL2: ' . $e->getMessage());
            return Yii::$app->response->redirect(Yii::$app->params['ssoLoginURL'] . "?redirect=" . $redirectURL);
        }
    }
}
