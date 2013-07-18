<?php

use fkooman\OAuth\Client\Api;
use fkooman\OAuth\Client\ClientConfig;
use fkooman\OAuth\Client\SessionStorage;
use Guzzle\Http\Client;
use fkooman\Guzzle\Plugin\BearerAuth\BearerAuth;
use fkooman\Guzzle\Plugin\BearerAuth\Exception\BearerErrorResponseException;

require_once "{INSTALL_DIR}/ssp/sp/lib/_autoload.php";
require_once 'vendor/autoload.php';

try {
    // first we login to this app...
    $as = new SimpleSAML_Auth_Simple('default-sp');
    $as->requireAuth();
    $attributes = $as->getAttributes();
    $userId = $attributes['uid'][0];

    /* OAuth client configuration */
    $clientConfig = ClientConfig::fromArray(array(
        "authorize_endpoint" => "{BASE_URL}/php-oauth/authorize.php",
        "client_id" => "php-voot-client",
        "client_secret" => "f00b4r",
        "token_endpoint" => "{BASE_URL}/php-oauth/token.php",
    ));

    /* the OAuth 2.0 protected URI */
    $apiUri = "{BASE_URL}/php-voot-proxy/voot.php/groups/@me";

    /* initialize the API */
    $api = new Api();
    $api->setClientConfig("php-voot-client", $clientConfig);
    $api->setStorage(new SessionStorage());
    $api->setHttpClient(new Client());

    /* the user to bind the tokens to */
    $api->setUserId($userId);

    /* the scope you want to request */
    $api->setScope(array("http://openvoot.org/groups"));

    $output = fetchTokenAndData($api, $apiUri);

    header("Content-Type: application/json");
    echo $output;

} catch (\Exception $e) {
    echo sprintf("ERROR: %s", $e->getMessage());
}

function fetchTokenAndData(Api $api, $apiUri)
{
    /* check if an access token is available */
    $accessToken = $api->getAccessToken();
    if (false === $accessToken) {
        /* no valid access token available, go to authorization server */
        header("HTTP/1.1 302 Found");
        header("Location: " . $api->getAuthorizeUri());
        exit;
    }

    /* we have an access token that appears valid */
    try {
        $client = new Client();
        $bearerAuth = new BearerAuth($accessToken->getAccessToken());
        $client->addSubscriber($bearerAuth);
        $response = $client->get($apiUri)->send();

        return $response->getBody();
    } catch (BearerErrorResponseException $e) {
        if ("invalid_token" === $e->getBearerReason()) {
            // the token we used was invalid, possibly revoked, we throw it away
            $api->deleteAccessToken();
            // and try again...
            return fetchTokenAndData($api, $apiUri);
        }
        throw $e;
    }

}
