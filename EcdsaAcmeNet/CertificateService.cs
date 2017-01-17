using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using log4net;

namespace EcdsaAcmeNet
{
    partial class EcdsaAcmeNetService : ServiceBase
    {
        public EcdsaAcmeNetService()
        {
            InitializeComponent();
        }

        private static bool isAlive;

        protected override void OnStart(string[] args)
        {
            log4net.Config.XmlConfigurator.Configure();
            var log = LogManager.GetLogger(typeof(EcdsaAcmeNetService));

            log.Info("Service started.");
            isAlive = true;

            Task.Factory.StartNew(() =>
            {
                try
                {
                    while (isAlive)
                    {
                        try
                        {
                            Program.ProcessConfigrationFolder(null, false, false, true, log);
                        }
                        catch (Exception e)
                        {
                            log.Error(e.Message, e);
                        }

                        // Config lookup every minute
                        Thread.Sleep(60 * 1000);
                    }
                }
                catch (Exception e)
                {
                    log.Error(e.Message, e);
                }
            });
        }

        protected override void OnStop()
        {
            log4net.Config.XmlConfigurator.Configure();
            var log = LogManager.GetLogger(typeof(EcdsaAcmeNetService));

            isAlive = false;

            log.Info("Service stopped.");
        }
    }
}
