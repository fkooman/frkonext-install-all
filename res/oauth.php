<?php

require_once "{INSTALL_DIR}/php-oauth-client/vendor/autoload.php";
require_once "{INSTALL_DIR}/ssp/sp/lib/_autoload.php";

try {
    // first we login to this app...
    $as = new SimpleSAML_Auth_Simple('default-sp');
    $as->requireAuth();
    $attributes = $as->getAttributes();
    $userId = $attributes['uid'][0];

    // then we go and obtain an access token and bind it to the
    // user logged into this application...
    $a = new \fkooman\OAuth\Client\Api("php-voot-client", $userId, array("http://openvoot.org/groups"));
    $a->setReturnUri("{BASE_URL}/php-voot-client/index.php");
    $response = $a->makeRequest("{BASE_URL}/php-voot-proxy/voot.php/groups/@me");
    header("Content-Type: application/json");
    echo $response->getBody();
} catch (Exception $e) {
    echo sprintf("Exception: %s", $e->getMessage());
}
