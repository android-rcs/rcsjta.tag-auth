#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

# remove existing keys
rm range* package* iari*

# create package signer cert and key.
echo "create package signer cert and key"
keytool -genkey -keyalg RSA -alias package-signer -keystore package-signer.jks -storepass secret -keypass secret -dname CN=package-signer-ext -validity 360 -keysize 2048
keytool -list -keystore package-signer.jks -storepass secret | grep fingerprint
