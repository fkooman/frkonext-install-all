<?php

use fkooman\OAuth\Client\ClientConfig;
use fkooman\OAuth\Client\Callback;
use fkooman\OAuth\Client\CallbackException;
use fkooman\OAuth\Client\SessionStorage;
use Guzzle\Http\Client;

require_once 'vendor/autoload.php';

/* OAuth client configuration */
$clientConfig = ClientConfig::fromArray(array(
    "authorize_endpoint" => "{BASE_URL}/php-oauth/authorize.php",
    "client_id" => "php-voot-client",
    "client_secret" => "f00b4r",
    "token_endpoint" => "{BASE_URL}/php-oauth/token.php",
));

try {
    /* initialize the API */
    $cb = new Callback();
    $cb->setClientConfig("php-voot-client", $clientConfig);
    $cb->setStorage(new SessionStorage());
    $cb->setHttpClient(new Client());

    /* handle the callback */
    $cb->handleCallback($_GET);

    header("HTTP/1.1 302 Found");
    header("Location: {BASE_URL}/php-voot-client/index.php");

} catch (CallbackException $e) {
    echo sprintf("ERROR: %s", $e->getMessage());
}
