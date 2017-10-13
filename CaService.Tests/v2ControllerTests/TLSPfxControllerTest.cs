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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;

namespace Ses.CaServiceTests.v2ControllerTests
{
    [TestFixture]
    public class TLSPfxControllerTest
    {
        private CaModel.certDBEntities db = new certDBEntities();
        private ClientCertManager clientCertManager = new ClientCertManager();
        private RootCertManager rootCertManager = new RootCertManager();
        private IntermediaryCertManager intermediaryCertManager = new IntermediaryCertManager();

        private X509Certificate2 rootCert;
        private X509Certificate2 intermediaryCert;
        private DateTime expirationDate = DateTime.Now.AddYears(1);

        private string rootCertEmail = "v2ControllerTestRootCert@test.com";
        private string rootCertName = "v2ControllerTestRootCert";
        private string intermediaryCertName = "v2ControllerTestIntermediaryCert";
        private string clientCertName = "clientUnitTestCert";
        private string clientCertEmail = "unittest@test.com";
        private string clientOrgName = "unittestOrganization";
        private string clientVendorId = "unittestVendorId";
        private string crlPath = "C:\\tmp\\test.crl";

        private List<string> certsToRemove = new List<string>();
        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        [SetUp]
        public void V2PfxControllerTestSetup()
        {
            // Remove all records in the database
            db.Certificates.RemoveRange(db.Certificates);
            db.TLSCertificates.RemoveRange(db.TLSCertificates);
            db.SaveChanges();

            // Ensure we have a Root tlsCert
            rootCert = RootCertManager.GetCertFromStore(rootCertName);
            if (null == rootCert)
            {  // Create root certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(rootCertEmail, rootCertName);
                rootCert = rootCertManager.CreateCert(dn, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(rootCert);
                certStore.Close();
            }

            // Ensure we have an Intermediary Cert
            intermediaryCert = RootCertManager.GetCertFromStore(intermediaryCertName);
            if (null == intermediaryCert)
            {  // Create intermediary certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(clientCertEmail, clientCertName);
                intermediaryCert = intermediaryCertManager.CreateCert(dn, rootCert, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(intermediaryCert);
                certStore.Close();
            }

            // Flush the cache
            ElastiCacheClient ecc = ElastiCacheClientFactory.GetClient();
            ecc.Flush();

            // Delete CRL File if it exists, and insert the test file
            if (File.Exists(crlPath))
            {
                File.Delete(crlPath);
            }
            File.Copy("..\\..\\..\\..\\DevOps\\testCRL.crl", crlPath);
        }

        [TearDown]
        public void V2PfxControllerTestTearDown()
        {
            // Remove local certs
            certStore.Open(OpenFlags.ReadWrite);
            certStore.Remove(rootCert);
            certStore.Remove(intermediaryCert);
            foreach (string certToRemove in certsToRemove)
            {
                BaseCertManager.RemoveCertFromStore(certToRemove);
            }
            certStore.Close();

            // Delete Database Records
            db.Certificates.RemoveRange(db.Certificates);
            db.TLSCertificates.RemoveRange(db.TLSCertificates);

            // Delete CertificateProfiles
            db.CertificateProfiles.RemoveRange(db.CertificateProfiles.Where(e => e.ProfileName.Contains("unittest")));
            db.SaveChanges();
        }

        [Test]
        public void TestCreateTLSPfx()
        {
            // First, assert that we have no existing tlsCert on record
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            TlsHelper th = CreateTLSHelper();
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Add another one to test the primary key issue we ran into
            th.CreatePfx("CN=" + clientOrgName + "2", "OU=" + clientVendorId, cp, DateTime.Now);
            Assert.AreEqual(2, db.TLSCertificates.Count());

            // Finally, assert that the response message is good
            // TODO

            // Cleanup
            certsToRemove.Add(clientOrgName);
            certsToRemove.Add(clientOrgName + "2");
        }

        [Test]
        public void TestGetTLSPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());
            TlsHelper th = CreateTLSHelper();
            V2PfxController v2c = CreateV2PfxController();

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Fourth, request the record
            IHttpActionResult actionResult = v2c.GetTLSPfx(clientOrgName, clientVendorId);

            var result = actionResult as BaseController.OctetStreamResult;
            Assert.NotNull(result);

            Task<HttpResponseMessage> msg = result.ExecuteAsync(CancellationToken.None);

            Assert.AreEqual("application/octet-stream", msg.Result.Content.Headers.ContentType.MediaType);
        }

        [Test]
        public void TestReissueTLSPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client tlsCert
            V2PfxController v2c = CreateV2PfxController();
            TlsHelper th = CreateTLSHelper();
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Reissue the tlsCert
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddYears(2);
            IHttpActionResult response = th.ReIssuePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, renewDate, crlPath);

            Task<HttpResponseMessage> msg = response.ExecuteAsync(CancellationToken.None);

            Assert.AreEqual("application/octet-stream", msg.Result.Content.Headers.ContentType.MediaType);
            System.Diagnostics.Debug.WriteLine("Reissue TLS Response Content: " + msg.Result.Content.ReadAsStringAsync().Result);

            // Assert that our response was a 200 success
            Assert.AreEqual(HttpStatusCode.OK.ToString(), msg.Result.StatusCode.ToString());

            // Assert that the date of our renewed tlsCert is equal to the one we passed in
            //X509Certificate2 renewedCert = v2c.GetTLSCertObjectFromDB("CN=" + clientOrgName, "OU=" + clientVendorId);
            //Assert.AreEqual(renewDate.ToShortDateString(), renewedCert.NotAfter.ToShortDateString());

            // Cleanup
            certsToRemove.Add(clientOrgName);
        }

        [Test]
        public void TestRenewTLSPfxSameSigner()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client tlsCert
            V2PfxController v2c = CreateV2PfxController();
            TlsHelper th = CreateTLSHelper();
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Renew the tlsCert
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddYears(2);
            //IHttpActionResult actionResult = th.RenewPfx("CN=" + clientOrgName, "OU=" + clientVendorId, renewDate);

            //var result = actionResult as BaseController.OctetStreamResult;
            //Assert.NotNull(result);

            //Task<HttpResponseMessage> msg = result.ExecuteAsync(CancellationToken.None);

            //Assert.AreEqual("application/octet-stream", msg.Result.Content.Headers.ContentType.MediaType);

            //Debug.WriteLine("Renew TLS Response Content: " + msg.Result.Content.ReadAsStringAsync().Result);

            // Assert that our response was a 200 success
            //Assert.AreEqual(HttpStatusCode.OK, msg.Result.StatusCode);

            // Assert that the date of our renewed tlsCert is equal to the one we passed in
            //X509Certificate2 renewedCert = v2c.GetTLSCertObjectFromDB("CN=" + clientOrgName, "OU=" + clientVendorId);
            //Assert.AreEqual(renewDate.ToShortDateString(), renewedCert.NotAfter.ToShortDateString());

            // Cleanup
            certsToRemove.Add(clientOrgName);
        }

        [Test]
        public void TestValidityPeriodCreateTLSPfx()
        {
            Assert.AreEqual(0, db.TLSCertificates.Count());
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());
            V2PfxController v2c = CreateV2PfxController();

            int validityPeriod = 25;
            CertificateRequest certRequest = new CertificateRequest()
            {
                orgName = clientOrgName,
                vendorId = clientVendorId,
                certProfileName = clientCertEmail,
                validityPeriod = validityPeriod
            };
            System.Diagnostics.Debug.WriteLine("certRequest: " + certRequest.orgName + "|" + certRequest.certProfileName);

            DateTime expirationDate = DateTime.Now.AddMonths(validityPeriod);
            IHttpActionResult actionResult = v2c.CreatePfx(certRequest);

            var result = actionResult as BaseController.OctetStreamResult;
            Assert.NotNull(result);

            Task<HttpResponseMessage> msg = result.ExecuteAsync(CancellationToken.None);

            Assert.AreEqual("application/octet-stream", msg.Result.Content.Headers.ContentType.MediaType);

            //if (response.Content != null)
            //{
            //    string responseMessage = response.Content.ReadAsStringAsync().Result;
            //    System.Diagnostics.Debug.WriteLine("responseMessage: " + responseMessage);
            //}

            //X509Certificate2 newCert = v2c.GetTLSCertObjectFromDB("CN=" + clientOrgName, "OU=" + clientVendorId);

            // Assertions
            //Assert.AreEqual(1, db.TLSCertificates.Count());
            //Assert.AreEqual(expirationDate.ToShortDateString(), newCert.NotAfter.ToShortDateString());

            // Cleanup
            certsToRemove.Add(clientCertName);
        }

        [Test]
        public void TestDoesTLSPfxExist()
        {
            // First, assert that an email tlsCert that doesn't exist does not exist.
            V2PfxController v2c = CreateV2PfxController();
            TlsHelper th = CreateTLSHelper();

            HttpResponseMessage response = v2c.CheckIfTLSPfxExists("Non-Extant Orgname", "Non-Extant VendorId");
            string responseString = response.Content.ReadAsStringAsync().Result;
            Assert.AreEqual("false", responseString);

            // Second, add a tlsCert
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Third, assert the tlsCert we just added exists.
            HttpResponseMessage existsResponse = v2c.CheckIfTLSPfxExists(clientOrgName, clientVendorId);
            string existsResponseString = existsResponse.Content.ReadAsStringAsync().Result;
            Assert.AreEqual("true", existsResponseString);

            // Some additional tests for when only one of the arguments are valid.
            HttpResponseMessage orgResponse = v2c.CheckIfTLSPfxExists(clientOrgName, "Non-Extant VendorId");
            string orgResponseString = orgResponse.Content.ReadAsStringAsync().Result;
            Assert.AreEqual("false", orgResponseString);

            HttpResponseMessage vendorResponse = v2c.CheckIfTLSPfxExists("Non-Extant VendorId", clientVendorId);
            string vendorResponseString = vendorResponse.Content.ReadAsStringAsync().Result;
            Assert.AreEqual("false", vendorResponseString);
        }

        [Test]
        public void TestGetTLSPin()
        {
            Assert.AreEqual(0, db.TLSCertificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            V2PfxController v2c = CreateV2PfxController();
            TlsHelper th = CreateTLSHelper();
            th.CreatePfx("CN=" + clientOrgName, "OU=" + clientVendorId, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Grab the pin from the database
            //string expectedPin = v2c.GetTLSPinFromDB("CN=" + clientOrgName, "OU=" + clientVendorId);
            //Assert.IsNotEmpty(expectedPin);

            // Request the pin from the API
           // HttpResponseMessage response = v2c.GetTLSPin(clientOrgName, clientVendorId);
            //string actualPin = response.Content.ReadAsStringAsync().Result;
            //Assert.AreEqual(expectedPin, actualPin);
        }

        [Test]
        public void TestDeleteTLSCert()
        {
            Assert.AreEqual(0, db.TLSCertificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            TlsHelper th = CreateTLSHelper();
            V2PfxController v2c = CreateV2PfxController();
            th.CreatePfx("CN=" + clientCertName, "OU=" + clientCertEmail, cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.TLSCertificates.Count());

            // Revoke the tlsCert, and assert that the entry is present in the CRL
            //X509Certificate2 clientCert = v2c.GetTLSCertObjectFromDB("CN=" + clientCertName, "OU=" + clientCertEmail);
            //th.RevokeAndDeletePfx("CN=" + clientCertName, "OU=" + clientCertEmail, cp, crlPath);
            //Org.BouncyCastle.X509.X509Certificate revokedCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(clientCert);
            //X509Crl crl = clientCertManager.GetCrlFromLocalMachine(crlPath);
            //Assert.IsTrue(crl.IsRevoked(revokedCert));
            //Assert.AreEqual(0, db.Certificates.Count());
        }

        private V2PfxController CreateV2PfxController()
        {
            V2PfxController v2c = new V2PfxController();
            v2c.Request = new HttpRequestMessage();
            v2c.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return v2c;
        }

        private TlsHelper CreateTLSHelper()
        {
            TlsHelper tlsHelper = new TlsHelper();
            tlsHelper.Request = new HttpRequestMessage();
            tlsHelper.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return tlsHelper;
        }

        private CertificateProfile CreateCertificateProfile(string profileName = "Integration-tsest Profile Name",
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