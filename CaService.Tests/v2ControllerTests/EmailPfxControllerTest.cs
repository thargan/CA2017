using CERTENROLLLib;
using NUnit.Framework;
using Org.BouncyCastle.X509;
using Ses.CaModel;
using Ses.CaService.Controllers.v2.Email;
using Ses.CaService.Controllers.v2.PfxHelpers;
using Ses.CaService.Crypto;
using Ses.CaService.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;
using System.Web.Http.Results;

namespace Ses.CaServiceTests.v2ControllerTests
{
    [TestFixture]
    public class EmailPfxControllerTest
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
        private string crlPath = "C:\\tmp\\test.crl";

        private List<string> certsToRemove = new List<string>();
        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        private EmailCertCreateRequest emailCertRequest;

        [SetUp]
        public void V2PfxControllerTestSetup()
        {
            // Remove all records in the database
            db.Certificates.RemoveRange(db.Certificates);
            db.SaveChanges();

            emailCertRequest = new EmailCertCreateRequest()
            {
                cname = clientCertName,
                email = clientCertEmail,
                orgName = "TestOrg",
                orgUnit = "TestOrgUnit",
                city = "testCity",
                state = "testState",
                country = "testCountry",
                certProfileName = clientCertEmail
            };

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

            // Delete CertificateProfiles
            db.CertificateProfiles.RemoveRange(db.CertificateProfiles.Where(e => e.ProfileName.Contains("unittest")));
            db.SaveChanges();
        }

        [Test]
        public void TestCreateEmailPfx()
        {
            // First, assert that we have no existing tlsCert on record
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            EmailHelper eh = CreateEmailHelper();
            IHttpActionResult response = eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Finally, assert that the response message is good
            Assert.IsInstanceOf<OkNegotiatedContentResult<System.String>>(response);

            // Cleanup
            certsToRemove.Add(clientCertName);
        }

        [Test]
        public void TestGetEmailPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            EmailPfxController controller = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Fourth, request the record
            IHttpActionResult response = controller.Get(clientCertEmail);

            // Assert we get a 200 response with a messageResultResult attached
            Assert.IsInstanceOf<ResponseMessageResult>(response);
        }

        [Test]
        public void TestGetEmailPrivateKey()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());

            // Second, create a client tlsCert
            EmailPfxController controller = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Third, assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Fourth, request the record
            IHttpActionResult response = controller.GetPrivateKey(clientCertEmail);

            // Assert we get a 200 response with a messageResultResult attached
            Assert.IsInstanceOf<ResponseMessageResult>(response);
        }

        [Test]
        public void TestGetPreviousEmailPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client tlsCert
            EmailPfxController v2c = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Reissue the tlsCert
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddYears(2);
            IHttpActionResult response = eh.ReIssuePfx(clientCertEmail, cp, renewDate, crlPath);

            // Assert that our response was a 200 success with a string in the response body
            Assert.IsInstanceOf<OkNegotiatedContentResult<System.String>>(response);

            // Assert that the old pin/pkey was recycled:
            Certificate dbRecord = v2c.GetEmailCertDBEntry(clientCertEmail);
            Assert.IsNotNull(dbRecord.LastEcryptionPIN);
            Assert.IsNotNull(dbRecord.LastPrivateKeyEncryption);

            // Fetch the last tlsCert, and assert that it's equal to the first one we created
            X509Certificate2 oldPfx = v2c.GetPreviousEmailCertObjectFromDB(clientCertEmail);
            Assert.AreEqual(originalDate.Date, oldPfx.NotAfter.Date);

            // Cleanup
            certsToRemove.Add(clientCertEmail);
        }

        [Test]
        public void TestReissueEmailPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client tlsCert
            EmailPfxController v2c = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Reissue the tlsCert
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddYears(2);

            IHttpActionResult response = eh.ReIssuePfx(clientCertEmail, cp, renewDate, crlPath);

            // Assert that our response was a 200 success with a string in the response body
            Assert.IsInstanceOf<OkNegotiatedContentResult<System.String>>(response);

            // Assert that the date of our renewed tlsCert is equal to the one we passed in
            X509Certificate2 renewedCert = v2c.GetEmailCertObjectFromDB(clientCertEmail);
            Assert.AreEqual(renewDate.ToShortDateString(), renewedCert.NotAfter.ToShortDateString());

            // Assert that the old pin/pkey was recycled:
            Certificate dbRecord = v2c.GetEmailCertDBEntry(clientCertEmail);
            Assert.IsNotNull(dbRecord.LastEcryptionPIN);
            Assert.IsNotNull(dbRecord.LastPrivateKeyEncryption);

            // Cleanup
            certsToRemove.Add(clientCertEmail);
        }

        [Test]
        public void TestRenewEmailPfxSameSigner()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client tlsCert
            EmailPfxController v2c = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Renew the tlsCert
            DateTime originalDate = DateTime.Now.AddMilliseconds(-DateTime.Now.Millisecond);
            DateTime renewDate = originalDate.AddYears(2);
            IHttpActionResult response = eh.RenewPfx(clientCertEmail, renewDate);

            // Assert that our response was a 200 success with a string in the response body
            Assert.IsInstanceOf<OkNegotiatedContentResult<System.String>>(response);

            // Assert that the date of our renewed tlsCert is equal to the one we passed in
            X509Certificate2 renewedCert = v2c.GetEmailCertObjectFromDB(clientCertEmail);
            Assert.AreEqual(renewDate.ToShortDateString(), renewedCert.NotAfter.ToShortDateString());

            // Cleanup
            certsToRemove.Add(clientCertEmail);
        }

        [Test]
        public void TestValidityPeriodCreateEmailPfx()
        {
            Assert.AreEqual(0, db.Certificates.Count());
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());
            EmailPfxController controller = new EmailPfxController();

            emailCertRequest.validityPeriod = 13;
            DateTime expectedExpirationDate = DateTime.Now.AddMonths(emailCertRequest.validityPeriod);

            IHttpActionResult response = controller.Create(emailCertRequest);
            X509Certificate2 newCert = controller.GetEmailCertObjectFromDB(clientCertEmail);

            // Assertions
            Assert.AreEqual(1, db.Certificates.Count());
            Assert.AreEqual(expectedExpirationDate.ToShortDateString(), newCert.NotAfter.ToShortDateString());

            // Cleanup
            certsToRemove.Add(clientCertName);
        }

        [Test]
        public void TestDoesEmailPfxExist()
        {
            // First, assert that an email tlsCert that doesn't exist does not exist.
            EmailPfxController controller = new EmailPfxController();
            IHttpActionResult response = controller.Exists("emailThatDoesNotExist@test.com");
            Assert.IsInstanceOf<OkNegotiatedContentResult<bool>>(response);
            OkNegotiatedContentResult<bool> result = response as OkNegotiatedContentResult<bool>;
            Assert.AreEqual(false, result.Content);

            // Second, add a tlsCert
            CertificateProfile cp = CreateCertificateProfile(clientCertEmail, rootCert.GetSerialNumberString());
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Third, assert the tlsCert we just added exists.
            IHttpActionResult existsResponse = controller.Exists(clientCertEmail);
            Assert.IsInstanceOf<OkNegotiatedContentResult<bool>>(existsResponse);
            OkNegotiatedContentResult<bool> existsResult = existsResponse as OkNegotiatedContentResult<bool>;
            Assert.AreEqual(true, existsResult.Content);
        }

        [Test]
        public void TestGetEmailPin()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientOrgName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            EmailPfxController controller = new EmailPfxController();
            EmailHelper eh = CreateEmailHelper();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Grab the pin from the database
            string expectedPin = controller.GetEmailPinFromDB(clientCertEmail);
            Assert.IsNotEmpty(expectedPin);

            // Request the pin from the API
            IHttpActionResult response = controller.GetPin(clientCertEmail);
            Assert.IsInstanceOf<OkNegotiatedContentResult<int>>(response);
            OkNegotiatedContentResult<int> result = response as OkNegotiatedContentResult<int>;
            Assert.AreEqual(int.Parse(expectedPin), result.Content);
        }

        [Test]
        public void TestDeleteEmailCert()
        {
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a CertificateProfile
            CertificateProfile cp = CreateCertificateProfile(clientCertName, rootCert.GetSerialNumberString());

            // Create a client email tlsCert
            EmailHelper eh = CreateEmailHelper();
            EmailPfxController controller = new EmailPfxController();
            eh.CreatePfx(clientCertEmail, emailCertRequest.GetDN(), cp, DateTime.Now);

            // Assert that we have one record in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Delete the tlsCert, and assert that the entry is present in the CRL and that the DB is empty
            X509Certificate2 clientCert = controller.GetEmailCertObjectFromDB(clientCertEmail);
            eh.RevokeAndDeletePfx(clientCertEmail, cp, crlPath);
            Org.BouncyCastle.X509.X509Certificate revokedCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(clientCert);
            X509Crl crl = clientCertManager.GetCrlFromLocalMachine(crlPath);

            Assert.IsTrue(crl.IsRevoked(revokedCert));
            Assert.AreEqual(0, db.Certificates.Count());
        }

        private EmailHelper CreateEmailHelper()
        {
            EmailHelper emailHelper = new EmailHelper();
            emailHelper.Request = new HttpRequestMessage();
            emailHelper.Request.SetConfiguration(new System.Web.Http.HttpConfiguration());
            return emailHelper;
        }

        private CertificateProfile CreateCertificateProfile(string profileName = "Integration-test Profile Name",
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