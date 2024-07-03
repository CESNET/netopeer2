# TLS support

If TLS is enabled in libnetconf2, the TLS functionality is enabled.
However, in order to make it working, you must perform a few initial
configuration tasks.

## client certificate

With every action that requires verification, you can specify
paths to the client certificate to be used. Also, if you do not
specify any certificate, the default one will be used. To set it
up, use the `cert replaceown` command.

## server certificate verification

In order to verify the certificate provided by the server, you
need to specify the Certificate Authority certificates you find
trustworthy and make them accessible to netopeer-cli. Again, you
can explicitly specify the path to a Certificate Authority
trusted store, or use the default directory. To add certificates
to this directory, use the `cert add` command.

## Certificate Revocation Lists
CRLs are automatically downloaded from URIs specified in the
x509 CRLDistributionPoints extensions of set certificates.
Be wary that if any configured certificate has this extension,
then a CRL issued by the server's CA has to be present for the connection to succeed. 

## Certificates

The `netopeer2/example_configuration/tls_certs` directory includes copies of the needed example
client certificates, which will work with the server example
certificates.

# Scripts

The CLI supports some basic scripting and an example `sample_script.sh`
is included for illustration.
