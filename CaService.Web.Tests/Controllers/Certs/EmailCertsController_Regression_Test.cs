using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Core;
using Ses.CaService.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CaService.Web.Tests
{
    [Ignore]
    [TestClass]
    public class EmailCertsController_Regression_Test
    {
        [AssemblyInitialize]
        public static void Configure(TestContext tc)
        {
            log4net.Config.XmlConfigurator.Configure();
        }

        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(EmailCertsController_Regression_Test));

        [TestMethod]
        public void RunRegressionTest()
        {
            _log.Info("START - REGRESSION TEST - START");

            EmailCertsController_POST_IntegrationTests post = new EmailCertsController_POST_IntegrationTests();
            post.Create_Professional__Returns_EmailCertResponse();
            post.CleanupTestData();
            post.Create_Patient__Returns_EmailCertResponse();

            EmailCertsController_PUT_Tests put = new EmailCertsController_PUT_Tests();
            put.Renew_Professional__Returns_EmailCertResponse();
            put.CleanupTestData();
            put.Renew_Patient__Returns_EmailCertResponse();
            
            _log.Info("END - REGRESSION TEST - END");
        }
    }
}
