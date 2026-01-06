using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using CommandLine;
using log4net;
using Microsoft.Web.Administration;
using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

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

        [Option('k', "keysize", HelpText = "Key size.")]
        public int KeySize { get; set; } = 256;
    }
    
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            Options options;
            ParserResult<Options> parserResult;
            if ((args == null) || !args.Any() || (parserResult = Parser.Default.ParseArguments<Options>(args)).Errors.Any())
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                    new EcdsaAcmeNetService()
                };
                ServiceBase.Run(ServicesToRun);

                return;
            }

            options = parserResult.Value;

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
            var keySize = options.KeySize;

            await ProcessConfigrationFolder(password, isManualFtpUpload, options.Test, false, null, keySize);
        }

        private static void RemoveReadOnlyAttribute(string path)
        {
            foreach (var file in System.IO.Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
            {
                var attributes = File.GetAttributes(file);

                if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                {
                    attributes = attributes & ~FileAttributes.ReadOnly;
                    File.SetAttributes(file, attributes);
                }
            }
        }

        public static async Task ProcessConfigrationFolder(string password, bool isManualFtpUpload, bool isTest, bool isService, ILog log, int? keySize)
        { 
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

            var configurationFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Configuration");
            if (!System.IO.Directory.Exists(configurationFolder))
            {
                System.IO.Directory.CreateDirectory(configurationFolder);
            }

            RemoveReadOnlyAttribute(configurationFolder);

            var configurationXmls = System.IO.Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories);
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

            foreach (var configurationPath in System.IO.Directory.GetFiles(configurationFolder, "*.xml", SearchOption.AllDirectories))
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
                    if (((passwordElement == null) || string.IsNullOrWhiteSpace(passwordElement.Value)) && string.IsNullOrWhiteSpace(password))
                    {
                        password = Guid.NewGuid().ToString("N");
                        if (log != null)
                        {
                            log.Info("Password not received. Generated this one: " + password);
                        }
                        Console.WriteLine("Password not received. Generated this one: " + password);
                    }
                    else if ((passwordElement != null) && !string.IsNullOrWhiteSpace(passwordElement.Value))
                    {
                        password = passwordElement.Value;
                    }

                    var keySizeElement = xmlDoc.Root.Elements(CommonNames.KeySize).FirstOrDefault();
                    if (((keySizeElement == null) || string.IsNullOrWhiteSpace(keySizeElement.Value)) && (keySize == null))
                    {
                        keySize = 256;
                        if (log != null)
                        {
                            log.Info("KeySize not received. Set to 256.");
                        }
                        Console.WriteLine("KeySize not received. Set to 256.");
                    }
                    else if ((keySizeElement != null) && !string.IsNullOrWhiteSpace(keySizeElement.Value))
                    {
                        keySize = int.Parse(keySizeElement.Value);
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

                    var source = isTest ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

                    AcmeContext acme = null;

                    try
                    {
                        var folder = Path.GetDirectoryName(configurationPath);
                        if (!File.Exists(Path.Combine(folder, "account.pem")))
                        {
                            var tmp = new AcmeContext(source);
                            await tmp.NewAccount(email, true);

                            var pemKey = tmp.AccountKey.ToPem();
                            File.WriteAllText(Path.Combine(folder, "account.pem"), pemKey);
                            
                            acme = tmp;
                        }
                        else
                        {
                            var accountKey = KeyFactory.FromPem(File.ReadAllText(Path.Combine(folder, "account.pem")));
                            var tmp = new AcmeContext(source, accountKey);
                            await tmp.Account();
                            
                            acme = tmp;
                        }
                    }
                    catch (Exception e)
                    {
                        if (log != null)
                        {
                            log.Error(e.Message, e);
                        }

                        continue;
                    }

                    var order = await acme.NewOrder(aliases);
                    var isValid = false;

                    Thread.Sleep(TimeSpan.FromSeconds(1));

                    foreach (var authz in (await order.Authorizations()).Where(x => x != null).ToList())
                    {
                        isValid = true;

                        if (authz.RetryAfter > 0)
                        {
                            Thread.Sleep(authz.RetryAfter);
                        }
                        else
                        {
                            Thread.Sleep(TimeSpan.FromSeconds(1));
                        }

                        var httpChallenge = await authz.Http();
                        while (httpChallenge == null)
                        {
                            httpChallenge = await authz.Http();
                            Thread.Sleep(TimeSpan.FromSeconds(1));
                        }

                        var keyAuthz = httpChallenge.KeyAuthz;

                        var answerPath = Environment.ExpandEnvironmentVariables(Path.Combine(webRootPath, ".well-known", "acme-challenge", httpChallenge.Token));

                        if (!isManualFtpUpload)
                        {
                            if (!System.IO.Directory.Exists(Path.GetDirectoryName(answerPath)))
                            {
                                System.IO.Directory.CreateDirectory(Path.GetDirectoryName(answerPath));
                            }

                            if (string.IsNullOrWhiteSpace(Path.GetExtension(answerPath)))
                            {
                                answerPath += ".softj";
                            }

                            File.WriteAllText(answerPath, keyAuthz);

                            if (answerPath.EndsWith(".softj"))
                            {
                                answerPath = answerPath.Replace(".softj", string.Empty);

                                if (File.Exists(answerPath))
                                {
                                    File.Delete(answerPath);
                                }

                                File.Move(answerPath + ".softj", answerPath);
                            }

                            Thread.Sleep(TimeSpan.FromSeconds(1));
                        }

                        if (isManualFtpUpload)
                        {
                            Console.WriteLine(string.Format("Deliver file {0} to your site hosting to folder .well-known\\acme-challenge and hit any key.", Path.GetFileName(answerPath)));
                            Console.ReadLine();
                        }

                        var result = await httpChallenge.Validate();
                        
                        while (result == null ||
                               result.Status == ChallengeStatus.Processing ||
                               result.Status == ChallengeStatus.Pending)
                        {
                            result = await httpChallenge.Resource();

                            Thread.Sleep(1000);
                        }

                        if (result.Status == ChallengeStatus.Invalid)
                        {
                            isValid = false;

                            if (log != null)
                            {
                                log.Error("Failed to validate http01 challenge for " + authz.Location);
                            }
                            Console.WriteLine("Failed to validate http01 challenge for " + authz.Location);
                        }
                    }

                    if (!isValid)
                    {
                        continue;
                    }

                    var privateKey = KeyFactory.NewKey(keySize == 256 ? KeyAlgorithm.ES256 : KeyAlgorithm.ES384);

                    Thread.Sleep(TimeSpan.FromSeconds(1));

                    var cert = await order.Generate(new CsrInfo
                    {
                        CommonName = aliases.First(),
                    }, privateKey);

                    var pfxBuilder = cert.ToPfx(privateKey);
                    var pfx = pfxBuilder.Build(aliases.First(), password);
                    File.WriteAllBytes(pfxfile, pfx);

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
