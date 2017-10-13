using CERTENROLLLib;
using NUnit.Framework;
using Ses.CaService.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Ses.CaServiceTests
{

    [TestFixture]
    class CertManagerMigrationTest
    {
        private AriCertManager oldCertManager = new AriCertManager();
        private RootCertManager rootCertManager = new RootCertManager();
        private ClientCertManager clientCertManager = new ClientCertManager();
        private IntermediaryCertManager intermediaryCertManager = new IntermediaryCertManager();

        private List<string> certsToRemove = new List<string>();
        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        private X509Certificate2 signingCert;
        private string signingCertEmail = "testSigningCert@test.com";
        private string signingCertName = "testSigningCert";

        [SetUp]
        public void CertManagerSetup()
        {
            signingCert = RootCertManager.GetCertFromStore(signingCertName);
            if (null == signingCert)
            {  // Create signing certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(signingCertEmail, signingCertName);
                signingCert = rootCertManager.CreateCert(dn, DateTime.Now.AddYears(1));
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(signingCert);
                certStore.Close();
            }
        }
        [TearDown]
        public void CertManagerTeardown()
        {
            // Delete certs from the local machine
            BaseCertManager.RemoveCertFromStore(signingCertName);
            foreach (string certToRemove in certsToRemove)
            {
                BaseCertManager.RemoveCertFromStore(certToRemove);
            }
        }

        // TODO: Update for the new DN changes
        /*
        [Test]
        public void CompareRootCertsTest()
        {
            string subject = "CN=testRootCert";
            DateTime expirationDate = DateTime.Now;

            X509Certificate2 expectedCert = oldCertManager.CreateRootCert(subject, expirationDate);
                // TODO: DN
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName();
            X509Certificate2 newCert = rootCertManager.CreateCert(dn, expirationDate);

            //Assert.AreEqual(expectedCert.GetCertHashString(), newCert.GetCertHashString());
            //Assert.AreEqual(expectedCert.GetSerialNumberString(), newCert.GetSerialNumberString());
            //Assert.AreEqual(expectedCert.GetEffectiveDateString(), newCert.GetEffectiveDateString());
            // -- Not all properties can be identical, because the certs will have different Public and Private keys,
            // -- but the important thing is that the fields we can check appear to be equal
            Assert.AreEqual(expectedCert.Issuer, newCert.Issuer);
            Assert.AreEqual(expectedCert.Subject, newCert.Subject);
            Assert.AreEqual(expectedCert.GetType(), newCert.GetType());

            // New certManager fixes an error with UTC offsets, so calculate this
            int hoursUTCOffset = GetUTCHoursOffset();
            Assert.AreEqual(expectedCert.NotAfter.AddHours(hoursUTCOffset), newCert.NotAfter.AddHours(0));
            certsToRemove.Add(subject);
        }

        [Test]
        public void CompareClientCertsTest()
        {
            string cname = "testClientCert";
            string email = "testClientEmail@test.com";

            DateTime expirationDate = DateTime.Now;

            X509Certificate2 expectedCert = oldCertManager.CreateClientCert(cname, email, signingCert, expirationDate);
            // TODO: DN
            CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName();
            X509Certificate2 newCert = clientCertManager.CreateCert(dn, signingCert, expirationDate);

            Assert.AreEqual(expectedCert.Issuer, newCert.Issuer);
            Assert.AreEqual(expectedCert.Subject, newCert.Subject);
            Assert.AreEqual(expectedCert.GetType(), newCert.GetType());

            // New certManager fixes an error with UTC offsets, so calculate this
            int hoursUTCOffset = GetUTCHoursOffset();
            Assert.AreEqual(expectedCert.NotAfter.AddHours(hoursUTCOffset), newCert.NotAfter.AddHours(0));
            certsToRemove.Add(cname);
        }

        [Test]
        public void CompareIntermediaryCertsTest()
        {
            string subject = "CN=testIntermediaryCert";

            DateTime expirationDate = DateTime.Now;

            X509Certificate2 expectedCert = oldCertManager.CreateIntermediaryCert(subject, signingCert, expirationDate);
                // TODO: DN
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName();
            X509Certificate2 newCert = intermediaryCertManager.CreateCert(dn, signingCert, expirationDate);

            Assert.AreEqual(expectedCert.Issuer, newCert.Issuer);
            Assert.AreEqual(expectedCert.Subject, newCert.Subject);
            Assert.AreEqual(expectedCert.GetType(), newCert.GetType());

            // New certManager fixes an error with UTC offsets, so calculate this
            int hoursUTCOffset = GetUTCHoursOffset();
            Assert.AreEqual(expectedCert.NotAfter.AddHours(hoursUTCOffset), newCert.NotAfter.AddHours(0));
            certsToRemove.Add(subject);
        }
        */

        private int GetUTCHoursOffset()
        {
            int offset = DateTime.UtcNow.Hour - DateTime.Now.Hour;
            return offset < 0 ? offset + 24 : offset;
        }
    }
}
