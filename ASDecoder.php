<?php

namespace AppleSignIn;

use AppleSignIn\Vendor\JWK;
use AppleSignIn\Vendor\JWT;

use Exception;

/**
 * Decode Sign In with Apple identity token, and produce an ASPayload for
 * utilizing in backend auth flows to verify validity of provided user creds.
 *
 * @package  AppleSignIn\ASDecoder
 * @author   Griffin Ledingham <gcledingham@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/GriffinLedingham/php-apple-signin
 * @link     https://github.com/wubuwei/php-apple-signin
 */
class ASDecoder
{
    /**
     * Parse a provided Sign In with Apple identity token.
     * @param $identityToken
     * @return ASPayload
     * @throws Exception
     */
    public static function getAppleSignInPayload($identityToken)
    {
        $identityPayload = self::decodeIdentityToken($identityToken);
        return new ASPayload($identityPayload);
    }

    /**
     * Decode the Apple encoded JWT using Apple's public key for the signing.
     * @param $identityToken
     * @return object
     * @throws Exception
     */
    public static function decodeIdentityToken($identityToken)
    {
        $publicKeyData = self::fetchPublicKey($identityToken);

        $publicKey = $publicKeyData['publicKey'];
        $alg = $publicKeyData['alg'];
        $payload = JWT::decode($identityToken, $publicKey, [$alg]);
        return $payload;
    }

    /**
     * Fetch Apple's public key from the auth/keys REST API to use to decode
     * the Sign In JWT.
     *
     * @param $identityToken
     * @return array
     * @throws Exception
     */
    public static function fetchPublicKey($identityToken)
    {
        $publicKeys = file_get_contents('https://appleid.apple.com/auth/keys');
        $decodedPublicKeys = json_decode($publicKeys, true);

        if (!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
            throw new Exception('Invalid key format.');
        }

        // 苹果公钥返回的 keys 内数据不是固定顺序，此处按索引取 auth keys，取正确的 key
        // value by index
        try {
            $tks = explode('.', $identityToken);
            if (count($tks) != 3) {
                throw new Exception('Wrong number of segments');
            }
            list($headb64, $bodyb64, $cryptob64) = $tks;
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64));
            $kid = $header->kid;

            if (count($decodedPublicKeys['keys']) > 1) {
                $indexPublicInfo = array_column($decodedPublicKeys['keys'], null, 'kid');
                $parsedKeyData = isset($indexPublicInfo[$kid]) ? $indexPublicInfo[$kid] : $decodedPublicKeys['keys'][0];
            } else {
                $parsedKeyData = $decodedPublicKeys['keys'][0];
            }
        } catch (\Exception $exception) {
            $parsedKeyData = $decodedPublicKeys['keys'][0];
        }

        $parsedPublicKey = JWK::parseKey($parsedKeyData);
        $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);

        if (!isset($publicKeyDetails['key'])) {
            throw new Exception('Invalid public key details.');
        }

        return [
            'publicKey' => $publicKeyDetails['key'],
            'alg'       => $parsedKeyData['alg']
        ];
    }
}

/**
 * A class decorator for the Sign In with Apple payload produced by
 * decoding the signed JWT from a client.
 */
class ASPayload
{
    protected $_instance;

    public function __construct($instance)
    {
        if (is_null($instance)) {
            throw new Exception('ASPayload received null instance.');
        }
        $this->_instance = $instance;
    }

    public function __call($method, $args)
    {
        return call_user_func_array(array($this->_instance, $method), $args);
    }

    public function __get($key)
    {
        return $this->_instance->$key;
    }

    public function __set($key, $val)
    {
        return $this->_instance->$key = $val;
    }

    public function getEmail()
    {
        return (isset($this->_instance->email)) ? $this->_instance->email : null;
    }

    public function getUser()
    {
        return (isset($this->_instance->sub)) ? $this->_instance->sub : null;
    }

    public function verifyUser($user)
    {
        return $user === $this->getUser();
    }

}
