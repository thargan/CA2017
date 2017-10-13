using CERTENROLLLib;
using NUnit.Framework;
using Org.BouncyCastle.X509;
using Ses.CaModel;
using Ses.CaService.Controllers;
using Ses.CaService.Controllers.v2.PfxHelpers;
using Ses.CaService.Crypto;
using Ses.CaService.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Ses.CaServiceTests.v2ControllerTests
{
    [TestFixture]
    public class V2CertControllerTest
    {
        private CaModel.certDBEntities db = new certDBEntities();
        private ClientCertManager clientCertManager = new ClientCertManager();
        private RootCertManager rootCertManager = new RootCertManager();

        private X509Certificate2 rootCert;
        private DateTime expirationDate = DateTime.Now.AddYears(1);

        private string rootCertName = "v2ControllerTestRootCert";
        private string clientCertName = "clientUnitTestCert";
        private string clientCertEmail = "unittest@test.com";
        private string crlPath = "C:\\tmp\\test.crl";

        private List<string> certsToRemove = new List<string>();

        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        [SetUp]
        public void V2CertControllerTestSetup()
        {
            // Delete Database Records
            db.Certificates.RemoveRange(db.Certificates);
            db.TLSCertificates.RemoveRange(db.TLSCertificates);
            db.SaveChanges();

            // Ensure we have a Root tlsCert
            rootCert = RootCertManager.GetCertFromStore(rootCertName);
            if (null == rootCert)
            {  // Create root certificate if it doesn't exist
                // TODO: DN
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName();
                rootCert = rootCertManager.CreateCert(dn, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(rootCert);
                certStore.Close();
            }

            // Delete CRL File if it exists
            if (File.Exists(crlPath))
            {
                File.Delete(crlPath);
            }
            File.Copy("..\\..\\..\\..\\DevOps\\testCRL.crl", crlPath);
        }

        [TearDown]
        public void V2CertControllerTestTearDown()
        {
            // Remove local certs
            certStore.Open(OpenFlags.ReadWrite);
            certStore.Remove(rootCert);
            foreach (string certToRemove in certsToRemove)
            {
                BaseCertManager.RemoveCertFromStore(certToRemove);
            }
            certStore.Close();

            // Delete CertificateProfiles
            db.CertificateProfiles.RemoveRange(db.CertificateProfiles.Where(e => e.ProfileName.Contains("unittest")));
            db.SaveChanges();

            // Flush the Cache
            ElastiCacheClient ecc = ElastiCacheClientFactory.GetClient();
            ecc.Flush();
        }

        // TODO: Fix for new email helper
        /*
        [Test]
        public void testGetEmailCert()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            V2CertController v2c = CreateV2CertController();
            V2PfxController v2p = CreateV2PfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx("CN=" + clientCertName, "E=" + clientCertEmail, cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Fourth, request the record
            HttpResponseMessage response = v2c.GetEmailCert(clientCertEmail);
            Assert.NotNull(response.Content);
            Assert.AreEqual("application/octet-stream", response.Content.Headers.ContentType.MediaType);
        }

        [Test]
        public void TestDoesEmailCertExist()
        {
            // First, assert that an email tlsCert that doesn't exist does not exist.
            V2CertController v2c = CreateV2CertController();
            V2PfxController v2p = CreateV2PfxController();
            EmailHelper eh = CreateEmailHelper();

            HttpResponseMessage response = v2c.CheckIfEmailCertExists("emailThatDoesNotExist@test.com");
            string responseString = response.Content.ReadAsStringAsync().Result;
            Assert.AreEqual("false", responseString);

            // Second, add a tlsCert
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());
            eh.CreatePfx("CN=" + clientCertName, "E=" + clientCertEmail, cp, DateTime.Now);

            // Third, assert the tlsCert we just added exists.
            HttpResponseMessage existsResponse = v2c.CheckIfEmailCertExists(clientCertEmail);
            string existsResponseString = existsResponse.Content.ReadAsStringAsync().Result;
            System.Diagnostics.Debug.WriteLine(existsResponseString);
            Assert.AreEqual("true", existsResponseString);
        }

        [Test]
        public void TestRevokeEmailCert()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            EmailHelper eh = CreateEmailHelper();
            V2CertController v2c = CreateV2CertController();
            eh.CreatePfx("CN=" + clientCertName, "E=" + clientCertEmail, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Revoke the tlsCert, and assert that the entry is present in the CRL
            eh.RevokeCert("E=" + clientCertEmail, cp, crlPath);
            X509Certificate2 clientCert = v2c.GetEmailCertObjectFromDB("E=" + clientCertEmail);
            Org.BouncyCastle.X509.X509Certificate revokedCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(clientCert);
            X509Crl crl = clientCertManager.GetCrlFromLocalMachine(crlPath);
            Assert.IsTrue(crl.IsRevoked(revokedCert));
        }
        */

        [Test]
        public void TestRevokeTLSCert()
        {
            Assert.AreEqual(0, db.TLSCertificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            TlsHelper th = CreateTLSHelper();
            V2CertController v2c = CreateV2CertController();
            th.CreatePfx("CN=" + clientCertName, "OU=" + clientCertEmail, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Revoke the tlsCert, and assert that the entry is present in the CRL
            //th.RevokeCert("CN=" + clientCertName, "OU=" + clientCertEmail, cp, crlPath);
            //X509Certificate2 clientCert = v2c.GetTLSCertObjectFromDB("CN=" + clientCertName, "OU=" + clientCertEmail);
            //Org.BouncyCastle.X509.X509Certificate revokedCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(clientCert);
            //X509Crl crl = clientCertManager.GetCrlFromLocalMachine(crlPath);
            //Assert.IsTrue(crl.IsRevoked(revokedCert));
        }

        private V2PfxController CreateV2PfxController()
        {
            V2PfxController v2c = new V2PfxController();
            v2c.Request = new HttpRequestMessage();
            v2c.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return v2c;
        }

        private V2CertController CreateV2CertController()
        {
            V2CertController v2c = new V2CertController();
            v2c.Request = new HttpRequestMessage();
            v2c.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return v2c;
        }

        private EmailHelper CreateEmailHelper()
        {
            EmailHelper emailHelper = new EmailHelper();
            emailHelper.Request = new HttpRequestMessage();
            emailHelper.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return emailHelper;
        }

        private TlsHelper CreateTLSHelper()
        {
            TlsHelper tlsHelper = new TlsHelper();
            tlsHelper.Request = new HttpRequestMessage();
            tlsHelper.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return tlsHelper;
        }

        private CertificateProfile CreateCertificateProfile(string profileName = "UnitTest Profile Name",
                                                            string signingCertSerial = "533E17B88FEB479B415DE47184B7F056",
                                                            string crlurl = "http://testcrl.net/crl.crl",
                                                            string certPolicyOID = "0.0.0.0.0.0",
                                                            string loaPolicyOID = "1.1.1.1.1.1",
                                                            string ekuOID = "2.2.2.2.2.2")
        {
            DateTime createdDate = DateTime.Now;
            CertificateProfile newProfile = new CertificateProfile()
            {
                ProfileName = profileName,
                CRLURL = crlurl,
                SigningCertSerialNumber = signingCertSerial,
                CertPolicyOID = certPolicyOID,
                LOAPolicyOID = loaPolicyOID,
                EnhancedKeyUsageOID = ekuOID,
                DateCreated = createdDate
            };
            db.CertificateProfiles.Add(newProfile);
            db.SaveChanges();

            return newProfile;
        }
    }
}