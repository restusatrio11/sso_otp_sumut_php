<?php

use sso_otp_sumut\JwtAuthentication\JWTAuthenticator;

class SiteController extends Controller
{

public function beforeAction($action)
{
    // Panggil komponen JWTAuthenticator untuk memverifikasi token sebelum aksi dijalankan
    $authenticator = new JWTAuthenticator();
    $authResult = $authenticator->authenticate();

    // Jika hasilnya berupa redirect, maka proses ini akan menghentikan eksekusi dan redirect.
    if ($authResult) {
        return $authResult;
    }


    return parent::beforeAction($action);
}

public function actionIndex()
{
    // Aksi yang akan dijalankan setelah token berhasil diverifikasi
    // Contoh: Ambil data, tampilkan, atau lakukan apa saja yang diinginkan
}

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
        
        // Mengatur waktu kedaluwarsa cookie tokenApp ke waktu yang sudah lewat
        Yii::$app->response->cookies->add(new \yii\web\Cookie([
            'name' => 'tokenApp',
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
}