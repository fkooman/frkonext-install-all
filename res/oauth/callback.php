<?php

require_once 'vendor/autoload.php';

/* OAuth client configuration */
$clientConfig = new \fkooman\OAuth\Client\ClientConfig(
    array(
        "authorize_endpoint" => "{BASE_URL}/php-oauth/authorize.php",
        "client_id" => "php-voot-client",
        "client_secret" => "f00b4r",
        "token_endpoint" => "{BASE_URL}/php-oauth/token.php",
    )
);

try {
    $tokenStorage = new \fkooman\OAuth\Client\SessionStorage();
    $httpClient = new \Guzzle\Http\Client();
    $cb = new \fkooman\OAuth\Client\Callback("php-voot-client", $clientConfig, $tokenStorage, $httpClient);
    $cb->handleCallback($_GET);

    header("HTTP/1.1 302 Found");
    header("Location: {BASE_URL}/php-voot-client/index.php");
    exit;
} catch (\fkooman\OAuth\Client\AuthorizeException $e) {
    // this exception is thrown by Callback when the OAuth server returns a
    // specific error message for the client, e.g.: the user did not authorize
    // the request
    die(sprintf("ERROR: %s, DESCRIPTION: %s", $e->getMessage(), $e->getDescription()));
} catch (\Exception $e) {
    // other error, these should never occur in the normal flow
    die(sprintf("ERROR: %s", $e->getMessage()));
}
