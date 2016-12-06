using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ACMESharp;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace EcdsaAcmeNet
{
    public class CertificateManager
    {
        public static string GetIssuerCertificate(string certificatePath, CertificateRequest certificate, Options options)
        {
            var linksEnum = certificate.Links;
            if (linksEnum != null)
            {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault("up");
                if (upLink != null)
                {
                    var temporaryFileName = Path.GetTempFileName();
                    try
                    {
                        using (var web = new WebClient())
                        {
                            var uri = new Uri(new Uri(options.Test ? Utils.TestBaseUri : Utils.BaseUri), upLink.Uri);
                            web.DownloadFile(uri, temporaryFileName);
                        }

                        var cacert = new X509Certificate2(temporaryFileName);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(certificatePath, "ca-" + sernum + "-crt.der");
                        var cacertPemFile = Path.Combine(certificatePath, "ca-" + sernum + "-crt.pem");

                        if (!File.Exists(cacertDerFile))
                        {
                            File.Copy(temporaryFileName, cacertDerFile, true);
                        }

                        if (!File.Exists(cacertPemFile))
                        {
                            using (FileStream source = new FileStream(cacertDerFile, FileMode.Open), target = new FileStream(cacertPemFile, FileMode.Create))
                            {
                                var parser = new X509CertificateParser();
                                var cert = parser.ReadCertificate(source);

                                var pString = new StringBuilder();
                                var pWriter = new PemWriter(new StringWriter(pString));
                                pWriter.WriteObject(cert);
                                pWriter.Writer.Flush();

                                var bytes = Encoding.UTF8.GetBytes(pString.ToString());
                                target.Write(bytes, 0, bytes.Length);
                            }
                        }

                        return cacertPemFile;
                    }
                    finally
                    {
                        if (File.Exists(temporaryFileName))
                        {
                            File.Delete(temporaryFileName);
                        }
                    }
                }
            }

            return null;
        }

        public static void GetCertificate(EcdsaSigner signer, AcmeClient client, IList<string> dnsNames, string pfxFile, string password, Options options)
        {
            if (!dnsNames.Any())
            {
                throw new ArgumentException("DNS name(s) must be specified!");
            }

            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new KeyGenerationParameters(secureRandom, Utils.KeySize);
            gen.Init(keyGenParam);
            var kp = gen.GenerateKeyPair();

            var sigFactory = new Asn1SignatureFactory("SHA" + signer.KeySize + "WITHECDSA", kp.Private);

            var name = new X509Name("CN=" + dnsNames[0]);

            Asn1Set attributes = null;
            if (dnsNames.Count > 0)
            {
                var names = new GeneralNames(dnsNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray());

                var sanSequence = new DerSequence(X509Extensions.SubjectAlternativeName, new DerOctetString(names));
                var container = new DerSequence(sanSequence);
                var extensionSet = new DerSet(container);
                var extensionRequest = new DerSequence(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, extensionSet);
                attributes = new DerSet(extensionRequest);
            }

            var csr = new Pkcs10CertificationRequest(sigFactory, name, kp.Public, attributes, kp.Private);

            var pemString = new StringBuilder();
            var pemWriter = new PemWriter(new StringWriter(pemString));
            pemWriter.WriteObject(csr);
            pemWriter.Writer.Flush();

            var pemKeyString = new StringBuilder();
            var pemKeyWriter = new PemWriter(new StringWriter(pemKeyString));
            pemKeyWriter.WriteObject(kp);
            pemKeyWriter.Writer.Flush();

            var derRaw = csr.GetDerEncoded();
            var derB64U = JwsHelper.Base64UrlEncode(derRaw);
            var certRequ = client.RequestCertificate(derB64U);

            if (certRequ.StatusCode == HttpStatusCode.Created)
            {
                var certificatePath = Path.GetDirectoryName(pfxFile);
                var keyPemFile = Path.Combine(certificatePath, dnsNames[0] + "-key.pem");
                var csrPemFile = Path.Combine(certificatePath, dnsNames[0] + "-csr.pem");
                var crtDerFile = Path.Combine(certificatePath, dnsNames[0] + "-crt.der");
                var crtPemFile = Path.Combine(certificatePath, dnsNames[0] + "-crt.pem");
                var chainPemFile = Path.Combine(certificatePath, dnsNames[0] + "-chain.pem");

                var cp = CertificateProvider.GetProvider();
                using (var fs = new FileStream(keyPemFile, FileMode.Create))
                {
                    var bytes = Encoding.UTF8.GetBytes(pemKeyString.ToString());
                    fs.Write(bytes, 0, bytes.Length);
                }
                using (var fs = new FileStream(csrPemFile, FileMode.Create))
                {
                    var bytes = Encoding.UTF8.GetBytes(pemString.ToString());
                    fs.Write(bytes, 0, bytes.Length);
                }

                using (var file = File.Create(crtDerFile))
                {
                    certRequ.SaveCertificate(file);
                }

                Org.BouncyCastle.X509.X509Certificate crt;
                using (FileStream source = new FileStream(crtDerFile, FileMode.Open), target = new FileStream(crtPemFile, FileMode.Create))
                {
                    var parser = new X509CertificateParser();
                    crt = parser.ReadCertificate(source);

                    var pString = new StringBuilder();
                    var pWriter = new PemWriter(new StringWriter(pString));
                    pWriter.WriteObject(crt);
                    pWriter.Writer.Flush();

                    var bytes = Encoding.UTF8.GetBytes(pString.ToString());
                    target.Write(bytes, 0, bytes.Length);
                }

                var isuPemFile = GetIssuerCertificate(certificatePath, certRequ, options);

                using (FileStream intermediate = new FileStream(isuPemFile, FileMode.Open),
                    certificate = new FileStream(crtPemFile, FileMode.Open),
                    chain = new FileStream(chainPemFile, FileMode.Create))
                {
                    certificate.CopyTo(chain);
                    intermediate.CopyTo(chain);
                }

                using (var source = new FileStream(isuPemFile, FileMode.Open))
                {
                    var parser = new X509CertificateParser();
                    var isuCrt = parser.ReadCertificate(source);

                    var certEntry = new X509CertificateEntry(crt);
                    var certCaEntry = new X509CertificateEntry(isuCrt);

                    var store = new Pkcs12StoreBuilder().Build();

                    // Bundle together the private key, signed certificate and CA
                    store.SetKeyEntry(crt.SubjectDN.ToString() + "_key", new AsymmetricKeyEntry(kp.Private), new X509CertificateEntry[] {
                        certEntry,
                        certCaEntry
                    });

                    // Finally save the bundle as a PFX file
                    using (var filestream = new FileStream(pfxFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        store.Save(filestream, password.ToCharArray(), new SecureRandom());
                    }
                }

                cp.Dispose();
            }
        }
    }
}
