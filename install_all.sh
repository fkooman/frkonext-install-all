#!/bin/bash

if [ -z "$1" ]
then

cat << EOF
    Please specify the location to install to. 

    Examples:
    
    Fedora, CentOS, RHEL: /var/www/html/frkonext
    Debian, Ubuntu: /var/www/frkonext
    Mac OS X: /Library/WebServer/Documents/frkonext

    **********************************************************************
    * WARNING: ALL FILES IN THE INSTALLATION DIRECTORY WILL BE ERASED!!! *
    **********************************************************************

EOF
exit 1
else
    INSTALL_DIR=$1
fi

if [ -z "$2" ]
then
cat << EOF
    Please also specify the URL at which this installation will be available.

    Examples:

    http://localhost/frkonext
    https://www.example.edu/frkonext
    https://my.server.example.org

EOF
exit 1
else
    BASE_URL=$2
    BASE_PATH=`echo ${BASE_URL} | sed "s|[^/]*\/\/[^/]*||g"`
    DOMAIN_NAME=`echo ${BASE_URL} | sed "s|[^/]*\/\/||g" | sed "s|:.*||g" | sed "s|\/.*||g"`
    DATE_TIME=`date`
fi

SIMPLESAMLPHP_VERSION=trunk
SIMPLESAMLPHP_REVISION=3231    # only for trunk

cat << EOF
###############################################################################
# This script installs the following components to have a fully functional    #
# FrKoNext installation with all the components to quickly evaluate the       #
# software                                                                    #
#                                                                             #
# The following components will be installed:                                 #
#                                                                             #
# * simpleSAMLphp                                                             #
# * php-rest-service                                                          #
# * php-lib-remote-rs                                                         #
# * php-ssp-api                                                               #
# * php-oauth                                                                 #
# * html-manage-ssp                                                           #
# * html-manage-applications                                                  #
# * html-manage-authorization                                                 #
# * php-voot-proxy                                                            #
# * php-voot-provider                                                         #
# * html-voot-client                                                          #
# * voot-specification                                                        #
# * SAML Demo SP                                                              #
###############################################################################
EOF

if [ ! -d "${INSTALL_DIR}" ]
then
    echo "install dir ${INSTALL_DIR} does not exist (yet) make sure you created it and have write permission to it!";
    exit 1
fi

LAUNCH_DIR=`pwd`

# some simpleSAMLphp variables
SSP_ADMIN_PASSWORD=`env LC_CTYPE=C tr -c -d '0123456789abcdefghijklmnopqrstuvwxyz' </dev/urandom | dd bs=8 count=1 2>/dev/null;echo`

# remove the existing installation
echo "ARE YOU SURE YOU WANT TO ERASE ALL FILES FROM: '${INSTALL_DIR}/'?"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) break;;
        No ) exit;;
    esac
done

rm -rf ${INSTALL_DIR}/*

mkdir -p ${INSTALL_DIR}/downloads
mkdir -p ${INSTALL_DIR}/apache
mkdir -p ${INSTALL_DIR}/res

# the index page
cat ${LAUNCH_DIR}/res/index.html \
    | sed "s|{BASE_URL}|${BASE_URL}|g" \
    | sed "s|{ADMIN_PASSWORD}|${SSP_ADMIN_PASSWORD}|g" \
    | sed "s|{DATE_TIME}|${DATE_TIME}|g" > ${INSTALL_DIR}/index.html

# install the logos
cp ${LAUNCH_DIR}/res/*.png ${INSTALL_DIR}/res

# download simpleSAMLphp
if [ "trunk" == "${SIMPLESAMLPHP_VERSION}" ]
then
    # check it out from SVN
    (
        cd ${INSTALL_DIR}/downloads
        svn -q export -r ${SIMPLESAMLPHP_REVISION} http://simplesamlphp.googlecode.com/svn/trunk/ simplesamlphp-${SIMPLESAMLPHP_VERSION}
        (
            cd simplesamlphp-${SIMPLESAMLPHP_VERSION}
            cp config-templates/* config/
            cp metadata-templates/* metadata/
        )
        tar -czf simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz simplesamlphp-${SIMPLESAMLPHP_VERSION}
    )
else
    # download the tarball
    (
        cd ${INSTALL_DIR}/downloads
        curl -O https://simplesamlphp.googlecode.com/files/simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz
    )
fi

cat << EOF
#######################
# simpleSAMLphp Proxy #
#######################
EOF
(
cd ${INSTALL_DIR}
tar -xzf downloads/simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz
mkdir -p ssp
mv simplesamlphp-${SIMPLESAMLPHP_VERSION} ssp/proxy
cd ${INSTALL_DIR}/ssp/proxy

# generate proxy certificate
openssl req -subj '/O=Snake Oil, CN=Demo Proxy Service/' -newkey rsa:2048 -new -x509 -days 3652 -nodes -out cert/proxy.crt -keyout cert/proxy.pem

SSP_SECRET_SALT=`env LC_CTYPE=C tr -c -d '0123456789abcdefghijklmnopqrstuvwxyz' </dev/urandom | dd bs=32 count=1 2>/dev/null;echo`

# apply configuration patch to simpleSAMLphp
echo "[PATCH] simpleSAMLphp-proxy.diff"
cat ${LAUNCH_DIR}/config/simpleSAMLphp-proxy.diff \
    | sed "s|{INSTALL_DIR}|${INSTALL_DIR}|g" \
    | sed "s|{BASE_URL}|${BASE_URL}|g" \
    | sed "s|{ADMIN_PASSWORD}|${SSP_ADMIN_PASSWORD}|g" \
    | sed "s|{SECRET_SALT}|${SSP_SECRET_SALT}|g" \
    | sed "s|{DOMAIN_NAME}|${DOMAIN_NAME}|g" | patch -p1

# patch in PDO support
echo "[PATCH] simplesamlphp-add-pdo-metadata-source-v6.diff"
patch -p0 < ${LAUNCH_DIR}/res/simplesamlphp-add-pdo-metadata-source-v6.diff

# very weird default context: unconfined_u:object_r:user_tmp_t:s0, restore it
restorecon lib/SimpleSAML/Metadata/MetaDataStorageHandlerPdo.php

# enable some modules
touch modules/aggregator/enable

# Apache config
echo "Alias ${BASE_PATH}/sspproxy ${INSTALL_DIR}/ssp/proxy/www" > ${INSTALL_DIR}/apache/frkonext_sspproxy.conf
)

cat << EOF
#####################
# simpleSAMLphp IdP #
#####################
EOF
(
cd ${INSTALL_DIR}
tar -xzf downloads/simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz
mkdir -p ssp
mv simplesamlphp-${SIMPLESAMLPHP_VERSION} ssp/idp
cd ${INSTALL_DIR}/ssp/idp

# generate IdP certificate
openssl req -subj '/O=Snake Oil, CN=Demo Identity Provider/' -newkey rsa:2048 -new -x509 -days 3652 -nodes -out cert/idp.crt -keyout cert/idp.pem

SSP_SECRET_SALT=`env LC_CTYPE=C tr -c -d '0123456789abcdefghijklmnopqrstuvwxyz' </dev/urandom | dd bs=32 count=1 2>/dev/null;echo`

# apply configuration patch to simpleSAMLphp
echo "[PATCH] simpleSAMLphp-IdP.diff"
cat ${LAUNCH_DIR}/config/simpleSAMLphp-IdP.diff \
    | sed "s|{INSTALL_DIR}|${INSTALL_DIR}|g" \
    | sed "s|{BASE_URL}|${BASE_URL}|g" \
    | sed "s|{ADMIN_PASSWORD}|${SSP_ADMIN_PASSWORD}|g" \
    | sed "s|{SECRET_SALT}|${SSP_SECRET_SALT}|g" \
    | sed "s|{DOMAIN_NAME}|${DOMAIN_NAME}|g" | patch -p1

# enable the example-userpass module
touch modules/exampleauth/enable

# Apache config
echo "Alias ${BASE_PATH}/sspidp ${INSTALL_DIR}/ssp/idp/www" > ${INSTALL_DIR}/apache/frkonext_sspidp.conf
)

cat << EOF
####################
# simpleSAMLphp SP #
####################
EOF
(
cd ${INSTALL_DIR}
tar -xzf downloads/simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz
mkdir -p ssp
mv simplesamlphp-${SIMPLESAMLPHP_VERSION} ssp/sp
cd ${INSTALL_DIR}/ssp/sp

# convert the proxy certificate to a one-line base64 string
CERT_DATA=`cat ../proxy/cert/proxy.crt | grep -v 'CERTIFICATE' | tr -d '\n'`

SSP_SECRET_SALT=`env LC_CTYPE=C tr -c -d '0123456789abcdefghijklmnopqrstuvwxyz' </dev/urandom | dd bs=32 count=1 2>/dev/null;echo`

# apply configuration patch to simpleSAMLphp
echo "[PATCH] simpleSAMLphp-SP.diff"
cat ${LAUNCH_DIR}/config/simpleSAMLphp-SP.diff \
    | sed "s|{INSTALL_DIR}|${INSTALL_DIR}|g" \
    | sed "s|{BASE_URL}|${BASE_URL}|g" \
    | sed "s|{ADMIN_PASSWORD}|${SSP_ADMIN_PASSWORD}|g" \
    | sed "s|{SECRET_SALT}|${SSP_SECRET_SALT}|g" \
    | sed "s|{DOMAIN_NAME}|${DOMAIN_NAME}|g" \
    | sed "s|{CERT_DATA}|${CERT_DATA}|g" | patch -p1

# Apache config
echo "Alias ${BASE_PATH}/sspsp ${INSTALL_DIR}/ssp/sp/www" > ${INSTALL_DIR}/apache/frkonext_sspsp.conf
)

cat << EOF
#####################################
# php-rest-service (SHARED LIBRARY) #
#####################################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-rest-service.git
)
cat << EOF
######################################
# php-lib-remote-rs (SHARED LIBRARY) #
######################################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-lib-remote-rs.git
)

cat << EOF
###############
# php-ssp-api #
###############
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-ssp-api.git
cd php-ssp-api

mkdir extlib
ln -s ../../php-rest-service extlib/
ln -s ../../php-lib-remote-rs extlib/

sh docs/configure.sh
php docs/initDatabase.php

# convert the IdP certificate to a one-line base64 string
CERT_DATA=`cat ../ssp/idp/cert/idp.crt | grep -v "CERTIFICATE" | tr -d '\n'`

# import the entries in the database
mkdir tmp/
cat ${LAUNCH_DIR}/config/saml20-idp-remote.json \
    | sed "s|{BASE_URL}|${BASE_URL}|g" \
    | sed "s|{DOMAIN_NAME}|${DOMAIN_NAME}|g" \
    | sed "s|{CERT_DATA}|${CERT_DATA}|g" > tmp/saml20-idp-remote.json

cat ${LAUNCH_DIR}/config/saml20-sp-remote.json \
    | sed "s|{DOMAIN_NAME}|${DOMAIN_NAME}|g" \
    | sed "s|{BASE_URL}|${BASE_URL}|g" > tmp/saml20-sp-remote.json

cat config/config.ini \
    | sed "s|http://localhost/php-oauth/tokeninfo.php|${BASE_URL}/php-oauth/tokeninfo.php|g" \
    | sed "s|/var/simplesamlphp|${INSTALL_DIR}/ssp/proxy|g" > config/tmp_config.ini
mv config/tmp_config.ini config/config.ini

php docs/importJsonMetadataPdo.php tmp/

cat docs/apache.conf \
    | sed "s|/APPNAME|${BASE_PATH}/php-ssp-api|g" \
    | sed "s|/PATH/TO/APP|${INSTALL_DIR}/php-ssp-api|g" > ${INSTALL_DIR}/apache/frkonext_php-ssp-api.conf
)

cat << EOF
#############################
# html-webapp-deps (SHARED) #
#############################
EOF
(
cd ${INSTALL_DIR}
mkdir -p html-webapp-deps/js
mkdir -p html-webapp-deps/bootstrap

# jQuery
curl -o html-webapp-deps/js/jquery.js http://code.jquery.com/jquery.min.js

# JSrender (JavaScript Template Rendering for jQuery)
curl -o html-webapp-deps/js/jsrender.js https://raw.github.com/BorisMoore/jsrender/master/jsrender.js

# JSO (JavaScript OAuth 2 client)
curl -o html-webapp-deps/js/jso.js https://raw.github.com/andreassolberg/jso/master/jso.js

# Bootstrap
curl -o html-webapp-deps/bootstrap.zip http://twitter.github.com/bootstrap/assets/bootstrap.zip
(cd html-webapp-deps/ && unzip -q bootstrap.zip && rm bootstrap.zip)
)

cat << EOF
#############
# php-oauth #
#############
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-oauth.git
cd php-oauth

mkdir extlib
ln -s ../../php-rest-service extlib/

sh docs/configure.sh
php docs/initOAuthDatabase.php

# config
cat config/oauth.ini.defaults \
    | sed "s|authenticationMechanism = \"DummyResourceOwner\"|;authenticationMechanism = \"DummyResourceOwner\"|g" \
    | sed "s|;authenticationMechanism = \"SspResourceOwner\"|authenticationMechanism = \"SspResourceOwner\"|g" \
    | sed "s|allowResourceOwnerScopeFiltering = FALSE|allowResourceOwnerScopeFiltering = TRUE|g" \
    | sed "s|accessTokenExpiry = 3600|accessTokenExpiry = 28800|g" \
    | sed "s|/PATH/TO/APP|${INSTALL_DIR}/php-oauth|g" \
    | sed "s|enableApi = FALSE|enableApi = TRUE|g" \
    | sed "s|/var/simplesamlphp|${INSTALL_DIR}/ssp/sp|g" > config/oauth.ini

# Apache config
cat docs/apache.conf \
    | sed "s|/APPNAME|${BASE_PATH}/php-oauth|g" \
    | sed "s|/PATH/TO/APP|${INSTALL_DIR}/php-oauth|g" > ${INSTALL_DIR}/apache/frkonext_php-oauth.conf

# Register Clients
cat ${LAUNCH_DIR}/config/client_registrations.json \
    | sed "s|{BASE_URL}|${BASE_URL}|g" > docs/myregistration.json
php docs/registerClients.php docs/myregistration.json
)

cat << EOF
###################
# html-manage-ssp #
###################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/html-manage-ssp.git
cd html-manage-ssp
ln -s ../html-webapp-deps ext

# configure
cat config/config.js.default \
    | sed "s|http://localhost|${BASE_URL}|g" > config/config.js
)

cat << EOF
############################
# html-manage-applications #
############################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/html-manage-applications.git
cd html-manage-applications
ln -s ../html-webapp-deps ext

# configure
cat config/config.js.default \
    | sed "s|http://localhost|${BASE_URL}|g" > config/config.js
)

cat << EOF
##############################
# html-manage-authorizations #
##############################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/html-manage-authorizations.git
cd html-manage-authorizations
ln -s ../html-webapp-deps ext

# configure
cat config/config.js.default \
    | sed "s|http://localhost|${BASE_URL}|g" > config/config.js
)

cat << EOF
#####################
# php-voot-provider #
#####################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-voot-provider.git
cd php-voot-provider

mkdir extlib
ln -s ../../php-rest-service extlib/

sh docs/configure.sh
php docs/initVootDatabase.php
cat docs/apache.conf \
    | sed "s|/APPNAME|${BASE_PATH}/php-voot-provider|g" \
    | sed "s|/PATH/TO/APP|${INSTALL_DIR}/php-voot-provider|g" > ${INSTALL_DIR}/apache/frkonext_php-voot-provider.conf
)

cat << EOF
##################
# php-voot-proxy #
##################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/php-voot-proxy.git
cd php-voot-proxy

mkdir extlib
ln -s ../../php-rest-service extlib/
ln -s ../../php-lib-remote-rs extlib/

sh docs/configure.sh

cat config/proxy.ini \
    | sed "s|http://localhost/php-oauth/tokeninfo.php|${BASE_URL}/php-oauth/tokeninfo.php|g" > config/tmp_proxy.ini
mv config/tmp_proxy.ini config/proxy.ini

php docs/initProxyDatabase.php
cat docs/apache.conf \
    | sed "s|/APPNAME|${BASE_PATH}/php-voot-proxy|g" \
    | sed "s|/PATH/TO/APP|${INSTALL_DIR}/php-voot-proxy|g" > ${INSTALL_DIR}/apache/frkonext_php-voot-proxy.conf

# Register Providers
cat ${LAUNCH_DIR}/config/provider_registrations.json \
    | sed "s|{BASE_URL}|${BASE_URL}|g" > docs/myregistration.json
php docs/registerProviders.php docs/myregistration.json
)

cat << EOF
####################
# html-voot-client #
####################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/html-voot-client.git
cd html-voot-client
ln -s ../html-webapp-deps ext

# configure
cat config/config.js.default \
    | sed "s|http://localhost|${BASE_URL}|g" > config/config.js
)

cat << EOF
######################
# voot-specification #
######################
EOF
(
cd ${INSTALL_DIR}
git clone https://github.com/fkooman/voot-specification.git
)

cat << EOF
###################################
# SAML attribute list application #
###################################
EOF
(
mkdir -p ${INSTALL_DIR}/saml
cd ${INSTALL_DIR}/saml
cat ${LAUNCH_DIR}/res/saml.php \
    | sed "s|{INSTALL_DIR}|${INSTALL_DIR}|g" > ${INSTALL_DIR}/saml/index.php
)

# Done
echo "**********************************************************************"
echo "* INSTALLATION DONE                                                  *"
echo "**********************************************************************"
echo
echo Please visit ${BASE_URL}.
echo
