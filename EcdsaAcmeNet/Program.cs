using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml.Linq;
using ACMESharp;
using ACMESharp.ACME;
using CommandLine;
using CommandLine.Text;
using log4net;
using Microsoft.Web.Administration;

namespace EcdsaAcmeNet
{
    public class Options
    {
        [Option('p', "password", Required = true, HelpText = "Password for PFX files.")]
        public string Password { get; set; }

        [Option('m', "manual", HelpText = "Manual upload of challenge files.")]
        public bool Manual { get; set; }

        [Option('t', "test", HelpText = "Test mode - staging acme will be used.")]
        public bool Test { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this, current => HelpText.DefaultParsingErrorsHandler(this, current));
        }
    }
    
    internal class Program
    {
        private static void Main(string[] args)
        {
            var options = new Options();
            if (!Parser.Default.ParseArguments(args, options))
            {
                return;
            }

            var password = options.Password;
            var isManualFtpUpload = options.Manual;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 |SecurityProtocolType.Tls12;

            var configurationFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Configuration");
            if (!Directory.Exists(configurationFolder))
            {
                Directory.CreateDirectory(configurationFolder);
            }

            var configurationXmls = Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories);
            if (!configurationXmls.Any())
            {
                Console.WriteLine("No certificate configuration found!");

                return;
            }

            foreach (var configurationPath in Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories))
            {
                try
                {
                    var xmlDoc = XDocument.Load(configurationPath);
                    if (xmlDoc.Root.Name != CommonNames.CertificateConfiguration)
                    {
                        continue;
                    }

                    var email = xmlDoc.Root.Elements(CommonNames.Email).First().Value;

                    if (!email.StartsWith("mailto:"))
                    {
                        email = "mailto:" + email;
                    }

                    var domain = xmlDoc.Root.Elements(CommonNames.Domain).First().Value;
                    var webRootPath = xmlDoc.Root.Elements(CommonNames.WebRoot).First().Value;
                    var aliasesElement = xmlDoc.Root.Elements(CommonNames.Aliases).First();
                    var aliases = new List<string>();

                    foreach (var alias in aliasesElement.Elements(CommonNames.Alias))
                    {
                        aliases.Add(alias.Value);
                    }

                    var certname = domain + DateTime.Now.ToString("ddMMyyyyHHmm");
                    var pfxfile = Path.Combine(Path.GetDirectoryName(configurationPath), certname + ".pfx");
                    var iisSiteName = xmlDoc.Root.Elements(CommonNames.IisSiteName).First().Value;

                    using (var signer = new EcdsaSigner())
                    {
                        signer.Init();

                        using (var client = new AcmeClient(new Uri(options.Test ? Utils.TestBaseUri : Utils.BaseUri), new AcmeServerDirectory(), signer))
                        {
                            client.Init();
                            client.GetDirectory(true);
                            client.Register(new[] {email}); // creates registration for given email with new ECC key
                            client.UpdateRegistration(true, true); // accepts let's encrypt terms of use

                            var dnsIdentifiers = new List<string>();
                            dnsIdentifiers.AddRange(aliases);
                            var authStatus = new List<AuthorizationState>();

                            foreach (var dnsIdentifier in dnsIdentifiers)
                            {
                                var authzState = client.AuthorizeIdentifier(dnsIdentifier);
                                var challenge = client.DecodeChallenge(authzState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
                                var httpChallenge = challenge.Challenge as HttpChallenge;

                                // We need to strip off any leading '/' in the path
                                var filePath = httpChallenge.FilePath;
                                if (filePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                                {
                                    filePath = filePath.Substring(1);
                                }

                                var answerPath =
                                    Environment.ExpandEnvironmentVariables(Path.Combine(webRootPath, filePath));
                                if (!Directory.Exists(Path.GetDirectoryName(answerPath)))
                                {
                                    Directory.CreateDirectory(Path.GetDirectoryName(answerPath));
                                }

                                // Protection against extensionless file exception
                                if (string.IsNullOrWhiteSpace(Path.GetExtension(answerPath)))
                                {
                                    answerPath += ".ean";
                                }

                                File.WriteAllText(answerPath, httpChallenge.FileContent);

                                if (answerPath.EndsWith(".ean"))
                                {
                                    answerPath = answerPath.Replace(".ean", string.Empty);

                                    File.Move(answerPath + ".ean", answerPath);
                                }

                                try
                                {
                                    authzState.Challenges = new[] {challenge};

                                    if (isManualFtpUpload)
                                    {
                                        Console.WriteLine(string.Format("Deliver file {0} to your site hosting to folder .well-known\acme-challenge and hit any key.", Path.GetFileName(answerPath)));
                                        Console.ReadLine();
                                    }

                                    client.SubmitChallengeAnswer(authzState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

                                    while (authzState.Status == "pending")
                                    {
                                        Thread.Sleep(1000);
                                        var newAuthzState = client.RefreshIdentifierAuthorization(authzState);
                                        if (newAuthzState.Status != "pending")
                                        {
                                            authzState = newAuthzState;
                                        }
                                    }

                                    if (authzState.Status == "invalid")
                                    {
                                        Console.WriteLine("ACME challenge failed for domain: " + domain);
                                    }

                                    authStatus.Add(authzState);
                                }
                                finally
                                {
                                    if (authzState.Status == "valid")
                                    {
                                        try
                                        {
                                            if (File.Exists(answerPath))
                                            {
                                                File.Delete(answerPath);
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine(ex.Message);
                                        }
                                    }
                                }
                            }

                            if (authStatus.All(x => x.Status == "valid"))
                            {
                                CertificateManager.GetCertificate(signer, client, dnsIdentifiers, pfxfile, password, options);
                            }
                        }
                    }

                    if (!File.Exists(pfxfile))
                    {
                        Console.WriteLine("PFX file not found: " + pfxfile);

                        continue;
                    }

                    Console.WriteLine("Certificate issued: " + pfxfile);

                    if (!string.IsNullOrWhiteSpace(iisSiteName))
                    {
                        using (var serverManager = new ServerManager())
                        {
                            var site = serverManager.Sites[iisSiteName];

                            var sslBindings = site.Bindings.Where(x => x.Protocol == "https").ToList();

                            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

                            var pass = new SecureString();
                            foreach (var c in password)
                            {
                                pass.AppendChar(c);
                            }

                            var certificate = new X509Certificate2(pfxfile, pass);
                            store.Add(certificate);
                            Console.WriteLine("Certificate:" + pfxfile + " added to store.");

                            foreach (var sslBinding in sslBindings)
                            {
                                sslBinding.CertificateHash = certificate.GetCertHash();
                                sslBinding.CertificateStoreName = store.Name;
                                Console.WriteLine("Certificate: " + pfxfile + " set up for binding " + sslBinding.Host);
                            }

                            serverManager.CommitChanges();

                            store.Close();
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }
    }
}
