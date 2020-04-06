php-apple-signin
=======
PHP library to manage Sign In with Apple identifier tokens, and validate them server side passed through by the iOS client.

PHP 扩展包验证苹果授权登录后的参数 identifier tokens，确保 token 是真实的 Apple Id 授权的。

Installation
------------

Use composer to manage your dependencies and download php-apple-signin:

```bash
composer require wubuwei/php-apple-signin
```

Example
-------
```php
<?php
use AppleSignIn\ASDecoder;

$clientUser = "example_client_user";
$identityToken = "example_encoded_jwt";

$appleSignInPayload = ASDecoder::getAppleSignInPayload($identityToken);

/**
 * Obtain the Sign In with Apple email and user creds.
 */
$email = $appleSignInPayload->getEmail();
$user = $appleSignInPayload->getUser();

/**
 * Determine whether the client-provided user is valid.
 */
$isValid = $appleSignInPayload->verifyUser($clientUser);

?>
```
