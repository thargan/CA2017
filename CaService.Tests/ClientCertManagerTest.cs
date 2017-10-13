using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Ses.CaService.Crypto;
using System.Security.Cryptography.X509Certificates;
using log4net;
using CERTENROLLLib;

namespace CaServiceTests
{
    [TestFixture]
    class ClientCertManagerTest
    {
        X509Certificate2 rootCert;
        private RootCertManager rootCertManager = new RootCertManager();

        private ClientCertManager clientCertManager = new ClientCertManager();
        private DateTime expirationDate = DateTime.Now.AddYears(1);
        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        private string rootCertName = "ClientCertManagerRootTestCert";
        private string cname = "testClientCert";
        private string email = "testClientEmail@test.com";

        private List<string> certsToRemove = new List<string>();

        [SetUp]
        public void SetUp()
        {
            rootCert = RootCertManager.GetCertFromStore(rootCertName);
            if (null == rootCert)
            {  // Create root certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(email, rootCertName, "testOrg", "testOU", "testCity", "testState", "USA");
                rootCert = rootCertManager.CreateCert(dn, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(rootCert);
                certStore.Close();
            }
        }
        [TearDown]
        public void TearDown()
        {
            ClientCertManager.RemoveCertFromStore(rootCertName);
            ClientCertManager.RemoveCertFromStore(cname);
            foreach (string certToRemove in certsToRemove)
            {
                BaseCertManager.RemoveCertFromStore(certToRemove);
            }
        }

        [Test]
        public void RenewCertTest()
        {
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddMinutes(10);

            CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(email, cname, "testOrg", "testOU", "testCity", "testState", "USA");
            X509Certificate2 clientCert = clientCertManager.CreateCert(dn, rootCert, originalDate);
            Assert.AreEqual(originalDate.ToString(), clientCert.NotAfter.ToString());

            X509Certificate2 renewedCert = clientCertManager.RenewCert(clientCert, renewDate);
            Assert.AreEqual(renewDate.ToString(), renewedCert.NotAfter.ToString());
        }

        [Test]
        public void GetRootCertSerialTest()
        {
            X509Certificate2 masterRootCert = RootCertManager.GetCertFromStore("rootTestCert");
            string rootCertSerial = masterRootCert.GetSerialNumberString();
            Assert.NotNull(rootCertSerial);
        }
    }
}
