#!/bin/sh

export SAN="DNS: www.frkonext.org, DNS: frkonext.org, DNS: authn.frkonext.org, DNS: authz.frkonext.org, DNS: manage.frkonext.org, DNS: voot.frkonext.org"
openssl req \
	-new \
	-days 365 \
	-newkey rsa:2048 \
	-nodes \
	-keyout server.key \
	-config openssl.cnf \
	-x509 \
	-extensions v3_req \
	-subj '/CN=www.frkonext.org/' \
	-out server.crt

