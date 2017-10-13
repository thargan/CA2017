using CERTENROLLLib;
using log4net;
using NUnit.Framework;
using Ses.CaModel;
using Ses.CaService.Controllers.v1;
using Ses.CaService.Crypto;
using Ses.CaService.Models;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Ses.CaServiceTests
{
    /// <summary>
    /// This class tests the functions in the CertController class.
    /// If the tests are failing when first adding this code to your local machine, please check the following:
    ///
    /// 1. Ensure that everybody has Full Control of the root certificate created by these unit tests:
    ///     1a. Run 'mmc'
    ///     1b. File -> Add/Remove snap-in
    ///     1c. Add "Certificates" to the list
    ///     1d. Locate certificates by navigating to Certificates(Local Computer) -> Personal -> Certificates
    ///     1e. Right-click on rootTestCert -> All Tasks -> Manage Pirvate Keys
    ///     1f. Click "Add...", type "Everybody", press "Check names", hit OK
    /// 2. Ensure that the "spInsertUserEncryptPin" stored procedure exists on your local machine's SQL server
    /// 3. Ensure that "CreateKeys.sql" stored procedure has been run (CaService/CaService/App_Data)
    /// </summary>
    [TestFixture]
    public class CertControllerTest
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(CertControllerTest));

        private CertController certController = new CertController();
        private KeyController keyController = new KeyController();
        private CaModel.certDBEntities db = new certDBEntities();

        //private AriCertManager certManager = new AriCertManager();
        private ClientCertManager clientCertManager = new ClientCertManager();

        private RootCertManager rootCertManager = new RootCertManager();

        private X509Certificate2 rootCert;
        private DateTime expirationDate = DateTime.Now.AddYears(1);

        private string rootCertEmail = "CertControllerRootTestCert@test.com";
        private string rootCertName = "CertControllerRootTestCert";
        private string clientCertName = "clientTestCert";
        private string clientCertEmail = "test@test.com";

        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        [SetUp]
        public void CertControllerTestSetup()
        {
            // Remove all records in the database
            db.Certificates.RemoveRange(db.Certificates);
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
        }

        [TearDown]
        public void CertControllerTestTearDown()
        {
            certStore.Open(OpenFlags.ReadWrite);
            certStore.Remove(rootCert);
        }

        [Test]
        public void testGetCertsByEmail()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            createDbEntry();

            // Assert that we have one record in the DB
            Assert.AreEqual(1, db.Certificates.Count());

            // Assert that we get a correctly-formatted HttpResponseMessage back from the server
            //clientCertResponse = certController.GetCertsByEmail(clientCertEmail);
            //Assert.IsNotNullOrEmpty(clientCertResponse.ToString());
           // Assert.AreEqual(new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream"),clientCertResponse.Content.Headers.ContentType);
            //Assert.AreEqual("tlsCert.crt", clientCertResponse.Content.Headers.ContentDisposition.FileName);
        }

        [Test]
        public void testPut()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            createDbEntry();

            // Assert that we have one record in the DB
            Assert.AreEqual(1, db.Certificates.Count());

            // Capture the original information about the certificate
            //HttpResponseMessage clientCertResponse = certController.GetCertsByEmail(clientCertEmail);
            //var originalCert = clientCertResponse.Content;

            // Invoke PUT to create a new tlsCert
            //certController.Put(getClientCertRequest());

            // Make sure we still only have 1 record in the DB
            //Assert.AreEqual(1, db.Certificates.Count());

            // Request tlsCert again and make sure the new tlsCert is different
            //HttpResponseMessage newClientCertResponse = certController.GetCertsByEmail(clientCertEmail);
            //var newCert = newClientCertResponse.Content;
            //Assert.AreNotEqual(originalCert, newCert);
        }

        private void createDbEntry()
        {
            CertRequest clientCertRequest = getClientCertRequest();
            keyController.Add(clientCertRequest);
        }

        private CertRequest getClientCertRequest()
        {
            return createCertRequest(clientCertName, clientCertEmail, rootCert.GetSerialNumberString());
        }

        private CertRequest createCertRequest(string certName, string certEmail, string signingCertName)
        {
            CertRequest certRequest = new CertRequest();
            certRequest.cname = certName;
            certRequest.email = certEmail;
            certRequest.signingCertName = signingCertName;

            return certRequest;
        }
    }
}