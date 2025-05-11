# tls-tool

## Install Dependencies

[Install JavaConsoleKit into local system-wide Maven repository](https://github.com/philsch91/JavaConsoleKit?tab=readme-ov-file#install)
```
mvn install:install-file \
  -Dfile=./local-maven-repo/JavaConsoleKit-1.0-SNAPSHOT.jar \
  -DgroupId=com.schunker.java \
  -DartifactId=JavaConsoleKit \
  -Dversion=1.0-SNAPSHOT \
  -Dpackaging=jar \
  -DgeneratePom=true
```

## Deploy Dependencies

Deploy dependency into local project-specific Maven repository
```
mvn deploy:deploy-file \
  -Dfile=./local-maven-repo/JavaConsoleKit-1.0-SNAPSHOT.jar \
  -DgroupId=com.schunker.java \
  -DartifactId=JavaConsoleKit \
  -Dversion=1.0-SNAPSHOT \
  -Durl=file:./local-maven-repo/ \
  -DrepositoryId=local-maven-repo \
  -DupdateReleaseInfo=true
```

View Manifest File of Dependency
```
unzip -p local-maven-repo/JavaConsoleKit-1.0-SNAPSHOT.jar META-INF/MANIFEST.MF
```

## Download Dependencies
```
mvn dependency:resolve
```

## Verify Dependencies
```
mvn -X dependency:tree
mvn dependency:tree [-Ddetail=true] | grep <dependency-name>
```

## Test
```
mvn test
```

## Execute
```
# Windows
java -cp "C:\\dev\\philipp-schunker\\tls-tool\\target\\classes;C:\\dev\\philipp-schunker\\JavaConsoleKit\\target\\classes" com.schunker.tls.App
# Linux
java -cp "/mnt/c/dev/philipp-schunker/tls-tool/target/classes:/mnt/c/dev/philipp-schunker/JavaConsoleKit/target/classes" com.schunker.tls.App
java [-Djava.security.keystore.type=<pkcs12/jks> -Djavax.net.ssl.keyStoreType=<pkcs12/jks> -Djavax.net.ssl.trustStoreType=<pkcs12/jks> -Dhttps.proxyHost=proxy.hostname.com -Dhttps.proxyPort=8080 -Dhttp.nonProxyHosts="*.subd.tld.com|*.tld.com" -Djava.util.logging.config.file=src/main/resources/logging.properties -Djavax.net.debug=all -Dssl.SocketFactory.provider=WireLogSSLSocketFactory] -jar target/tls-tool-1.0-SNAPSHOT-shaded.jar
```

## Package
```
mvn [-X] clean package [-s|--settings settings.xml]
```

## Notes
The default truststore is located at `$JAVA_HOME/lib/security/cacerts`.
The default keytool is located at `$JAVA_HOME/bin/keytool`.

This tool is an alternative for the use of `openssl` and `keytool`.
There may be problems with the use of `*.pem` files containing more than one certificate.
If `openssl` and `keytool` are used to import a certificate in a `*.pem` file, the file should also contain the root and intermediate certificates preceding the certificate.

```
openssl x509 -outform der -in certificate.pem -out certificate.der
keytool -import -alias your-alias -keystore cacerts -file certificate.der
```
