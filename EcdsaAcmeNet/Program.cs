using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
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
        [Option('p', "password", HelpText = "Password for PFX files.")]
        public string Password { get; set; }

        [Option('m', "manual", HelpText = "Manual upload of challenge files.")]
        public bool Manual { get; set; }

        [Option('t', "test", HelpText = "Test mode - staging acme will be used.")]
        public bool Test { get; set; }

        [Option('i', "install", HelpText = "Installs as windows service.")]
        public bool Install { get; set; }

        [Option('u', "uninstall", HelpText = "Uninstalls windows service.")]
        public bool Uninstall { get; set; }

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
            if ((args == null) || !args.Any() || !Parser.Default.ParseArguments(args, options))
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                    new EcdsaAcmeNetService()
                };
                ServiceBase.Run(ServicesToRun);

                return;
            }

            if (options.Install)
            {
                ManagedInstallerClass.InstallHelper(new[] {Assembly.GetExecutingAssembly().Location});

                return;
            }

            if (options.Uninstall)
            {
                try
                {
                    EventLog.Delete("ServiceEcdsaAcmeNet");
                    EventLog.DeleteEventSource("ServiceEcdsaAcmeNet");
                }
                catch
                {
                    // supress
                }

                try
                {
                    ManagedInstallerClass.InstallHelper(new[] { "/u", Assembly.GetExecutingAssembly().Location });
                }
                catch
                {
                    // supress
                }

                return;
            }

            var password = options.Password;
            var isManualFtpUpload = options.Manual;

            ProcessConfigrationFolder(password, isManualFtpUpload, options.Test, false, null);
        }

        public static void ProcessConfigrationFolder(string password, bool isManualFtpUpload, bool isTest, bool isService, ILog log)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 |SecurityProtocolType.Tls12;

            var configurationFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Configuration");
            if (!Directory.Exists(configurationFolder))
            {
                Directory.CreateDirectory(configurationFolder);
            }

            var configurationXmls = Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories);
            if (!configurationXmls.Any())
            {
                if (log != null)
                {
                    log.Info("No certificate configuration found! " + configurationFolder);
                }
                Console.WriteLine("No certificate configuration found!");

                return;
            }

            var date = DateTime.Now.Date;

            foreach (var configurationPath in Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories))
            {
                try
                {
                    var xmlDoc = XDocument.Load(configurationPath);
                    if (xmlDoc.Root.Name != CommonNames.CertificateConfiguration)
                    {
                        if (log != null)
                        {
                            log.Info("No certificate configuration found! " + configurationFolder);
                        }
                        Console.WriteLine("No certificate configuration found!");

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

                    var lastIssuedDateElement = xmlDoc.Root.Elements(CommonNames.LastIssuedDate).FirstOrDefault();
                    if (lastIssuedDateElement == null)
                    {
                        lastIssuedDateElement = new XElement(CommonNames.LastIssuedDate, DateTime.MinValue.Ticks.ToString());
                        xmlDoc.Root.Add(lastIssuedDateElement);
                    }

                    var passwordElement = xmlDoc.Root.Elements(CommonNames.Password).FirstOrDefault();
                    if ((passwordElement == null) || string.IsNullOrWhiteSpace(password))
                    {
                        password = Guid.NewGuid().ToString("N");
                        if (log != null)
                        {
                            log.Info("Password not received. Generated this one: " + password);
                        }
                        Console.WriteLine("Password not received. Generated this one: " + password);
                    }
                    else
                    {
                        password = passwordElement.Value;
                    }

                    var lastIssuedDate = new DateTime(long.Parse(lastIssuedDateElement.Value));

                    // if running as windows service, certificates gets issued on first day of every month
                    if (isService && ((lastIssuedDate.Month == date.Month) && (lastIssuedDate.Year == date.Year)))
                    {
                        continue;
                    }

                    if (log != null)
                    {
                        log.Info("Certificate being issued for " + domain);
                    }

                    using (var signer = new EcdsaSigner())
                    {
                        signer.Init();

                        using (var client = new AcmeClient(new Uri(isTest ? Utils.TestBaseUri : Utils.BaseUri), new AcmeServerDirectory(), signer))
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
                                        if (log != null)
                                        {
                                            log.Error("ACME challenge failed for domain: " + domain);
                                        }
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
                                            if (log != null)
                                            {
                                                log.Error(ex.Message, ex);
                                            }
                                            Console.WriteLine(ex.Message);
                                        }
                                    }
                                }
                            }

                            if (authStatus.All(x => x.Status == "valid"))
                            {
                                CertificateManager.GetCertificate(signer, client, dnsIdentifiers, pfxfile, password, isTest);
                            }
                        }
                    }

                    if (!File.Exists(pfxfile))
                    {
                        if (log != null)
                        {
                            log.Error("PFX file not found: " + pfxfile);
                        }
                        Console.WriteLine("PFX file not found: " + pfxfile);

                        continue;
                    }

                    if (log != null)
                    {
                        log.Info("Certificate issued: " + pfxfile);
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

                            var certificate = new X509Certificate2(pfxfile, pass, 
                                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                            certificate.FriendlyName = certname;
                            store.Add(certificate);
                            if (log != null)
                            {
                                log.Info("Certificate:" + pfxfile + " added to store.");
                            }
                            Console.WriteLine("Certificate:" + pfxfile + " added to store.");

                            foreach (var sslBinding in sslBindings)
                            {
                                sslBinding.CertificateHash = certificate.GetCertHash();
                                sslBinding.CertificateStoreName = store.Name;
                                if (log != null)
                                {
                                    log.Info("Certificate: " + pfxfile + " set up for binding " + sslBinding.Host);
                                }
                                Console.WriteLine("Certificate: " + pfxfile + " set up for binding " + sslBinding.Host);
                            }

                            serverManager.CommitChanges();

                            store.Close();
                        }
                    }

                    lastIssuedDateElement.Value = DateTime.Now.Ticks.ToString();
                    xmlDoc.Save(configurationPath);
                }
                catch (Exception e)
                {
                    if (log != null)
                    {
                        log.Error(e.Message, e);
                    }
                    Console.WriteLine(e.Message);
                }
            }
        }
    }
}
