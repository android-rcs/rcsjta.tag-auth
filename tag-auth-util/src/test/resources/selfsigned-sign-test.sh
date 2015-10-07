#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

# echo remove old keys etc
rm iari-self-signed-authorization.xml
rm keys/*self-signed*

# generate new self-signed iari
echo "create self-signed iari"
java -jar ../../../build/libs/tag-auth-util-1.0.jar -generate -keyalg RSA -alias iari-self-signed-test -keystore keys/iari-self-signed-test.jks -storepass secret -keypass secret -dname CN=iari.self-signed.test -validity 360 -keysize 2048 -dest iari-self-signed-authorization.xml -v

# sign package with that iari
echo "create iari authorization for package"
java -jar ../../../build/libs/tag-auth-util-1.0.jar -sign -template iari-self-signed-authorization.xml -dest iari-self-signed-authorization.xml -alias iari-self-signed-test -keystore keys/iari-self-signed-test.jks -storepass secret -keypass secret -pkgname iari.selfsigned.test -pkgkeystore keys/package-signer.jks -pkgalias package-signer -pkgstorepass secret -v

# validate auth document
echo "validate signed iari authorization"
#java -jar ../../../../tag-auth-validator/build/iarivalidator.jar -d iari-self-signed-authorization.xml -pkgname iari.selfsigned.test -pkgkeystore keys/package-signer.jks -pkgalias package-signer -pkgstorepass secret -v
java -jar ../../../../tag-auth-validator/build/libs/tag-auth-validator-jre.jar -d iari-self-signed-authorization.xml -pkgname iari.selfsigned.test -pkgkeystore keys/package-signer.jks -pkgalias package-signer -pkgstorepass secret -v
