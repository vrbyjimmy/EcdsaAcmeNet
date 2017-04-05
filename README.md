# EcdsaAcmeNet
Simple [ACME](https://github.com/ietf-wg-acme/acme/) client based on [ACMESharp](https://github.com/ebekker/ACMESharp) and [BouncyCastle](https://github.com/bcgit/bc-csharp) to issue [ECDSA](https://blog.cloudflare.com/ecdsa-the-digital-signature-algorithm-of-a-better-internet/) certificates from [Let's Encrypt](https://letsencrypt.org/).

#Parameters
-p "password" : Password for created PFX file.

-t : Testing mode - staging ACME url will be used.

-m : Manual mode - Manual delivery of ACME http01 challenge. Client will ask to upload each file for challenge before requesting server response.

-i : install as windows service

-u : uninstall windows service

-k KeySize : KeySize for generated certificate. Defaults to 256. Supported are 256, 384.

If you run it without any parameters, it tries to run as windows service and you might get an error message indicating that it must first be installed as service. To run this as simple commandline some parameters must be specified, -p preferably.

#Configuration
Client expects XML configuration file for each domain in Configuration directory placed in application's folder.

Example:
[AppFolder]/Configuration/myweb.com/config.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<CertificateConfiguration>
  <Email>me@myweb.com</Email>
  <Domain>myweb.com</Domain>
  <WebRoot>C:\Webs\MyWeb\WWWRoot</WebRoot>
  <IisSiteName>MyWebIISSite</IisSiteName>
  <Aliases>
    <Alias>myweb.com</Alias>
    <Alias>www.myweb.com</Alias>
  </Aliases>
</CertificateConfiguration>
```

WebRoot folder is folder, where http01 challenge files will be placed (WebRoot\\.well-known\acme-challenge).

If IisSiteName is specified, client will attempt to install the certificate to the PC's store and set it up for all https bindings of given IIS site.

All generated certificate files will be placed to the same directory as given XML config.

#IIS configuration

Make sure that your IIS site can serve extensionless files. You should have following lines in your web.config.

```xml
<staticContent>
  <mimeMap fileExtension="." mimeType="text/html" />
</staticContent>
```

When installed as windows service new certificates are issued on first day in month.
All info about service doings gets logged into ServiceEcdsaAcmeNet application log.
