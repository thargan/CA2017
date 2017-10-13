using CERTENROLLLib;
using log4net;
using NUnit.Framework;
using Ses.CaModel;
using Ses.CaService.Controllers.v1;
using Ses.CaService.Crypto;
using Ses.CaService.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;

namespace Ses.CaServiceTests
{
    /// <summary>
    /// This class tests the functions in the KeyController class.
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
    public class KeyControllerTest
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(KeyControllerTest));

        private KeyController keyController = new KeyController();
        private CaModel.certDBEntities db = new certDBEntities();

        //private AriCertManager certManager = new AriCertManager();
        private RootCertManager rootCertManager = new RootCertManager();

        private ClientCertManager clientCertManager = new ClientCertManager();

        private X509Certificate2 rootCert;
        private X509Certificate2 clientCert;
        private DateTime expirationDate = DateTime.Now.AddYears(1);

        private string rootCertName = "keyControllerRootTestCert";
        private string clientCertName = "clientTestCert";
        private string clientCertEmail = "test@test.com";
        private List<string> certsToRemove = new List<string>();

        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        [SetUp]
        public void KeyControllerTestSetup()
        {
            // Remove all records in the database
            db.Certificates.RemoveRange(db.Certificates);
            db.SaveChanges();

            // Ensure we have a Root tlsCert
            rootCert = RootCertManager.GetCertFromStore(rootCertName);
            if (null == rootCert)
            {  // Create root certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName("root@test.com", rootCertName);
                rootCert = rootCertManager.CreateCert(dn, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(rootCert);
                certStore.Close();
            }

            // Ensure we have a client tlsCert
            clientCert = ClientCertManager.GetCertFromStore(clientCertName);
            if (null == clientCert)
            {    // Create client certificate if it doesn't exist
                CX500DistinguishedName dn = ClientCertManager.CreateDistinguishedName(clientCertEmail, clientCertName);
                clientCert = clientCertManager.CreateCert(dn, rootCert, expirationDate);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(clientCert);
                certStore.Close();
            }

            certsToRemove.Clear();
        }

        [TearDown]
        public void KeyControllerTestTearDown()
        {
            // DB entries are deleted in SetUp because if the test fails, entries are left in the DB
            // if we have DB clearing as part of the TearDown method

            // Delete certs from the local machine
            BaseCertManager.RemoveCertFromStore(clientCertName);
            BaseCertManager.RemoveCertFromStore(rootCertName);
            foreach (string certToRemove in certsToRemove)
            {
                BaseCertManager.RemoveCertFromStore(certToRemove);
            }
        }

        [Test]
        public void testAddInvalidBlankRequest()
        {
            // Assert that there are no records in the database
            Assert.AreEqual(0, db.Certificates.Count());

            // Create an invalid request object (missing{ data)
            CertRequest invalidRequest = new CertRequest();

            // Attempt to add invalid request, asserting that an Exception is raised
            Assert.Throws<Exception>(delegate
            {
                keyController.Add(invalidRequest);
            });

            // Assert that there are no records in the database
            Assert.AreEqual(0, db.Certificates.Count());
        }

        [Test]
        public void testAddWithoutSigningCert()
        {
            // Assert that there are no records in the database
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a valid request object, referencing a signing tlsCert that does not exist
            CertRequest noCertRequest = new CertRequest();
            noCertRequest.cname = "CN=testAddWithoutSigningCert";
            noCertRequest.email = "E=testAddWithoutSigningCert@test.com";
            noCertRequest.signingCertName = "CN=certThatDoesNotExist";

            // Attempt to add request, asserting that an Exception is raised because of no tlsCert
            Assert.Throws<Exception>(delegate
            {
                keyController.Add(noCertRequest);
            });

            // Assert that there are no records in hte database
            Assert.AreEqual(0, db.Certificates.Count());
        }

        [Test]
        public void testAddWithValidCert()
        {
            // Assert that there are no records in the database
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a valid request object, referencing a signing tlsCert that does exist
            string cname = "CN=testAddWithValidCert";
            CertRequest validRequest = new CertRequest();
            validRequest.cname = cname;
            validRequest.email = "E=testAddWithValidCert@test.com";
            validRequest.signingCertName = rootCert.GetSerialNumberString();

            // Add request
            keyController.Add(validRequest);

            // Assert that there are 1 records in hte database
            Assert.AreEqual(1, db.Certificates.Count());
            certsToRemove.Add(cname);
        }

        [Test]
        public void testAddWithEKU()
        {
            // Assert that there are no records in the database
            Assert.AreEqual(0, db.Certificates.Count());

            // Create a valid request object, passing a custom ExtendedKeyUsage OID
            string cname = "CN=testAddWithEKU";
            string email = "E=testAddWithEKU@test.com";
            CertRequest ekuRequest = new CertRequest();
            ekuRequest.cname = cname;
            ekuRequest.email = email;
            ekuRequest.signingCertName = rootCert.GetSerialNumberString();
            ekuRequest.ekuPolicyOID = OID.GetOIDString(OIDType.CLIENT_AUTH);

            keyController.Add(ekuRequest);

            // Assert that there are 1 records in hte database
            Assert.AreEqual(1, db.Certificates.Count());
            certsToRemove.Add(cname);
        }

        [Test]
        public void testGetKeysByEmail()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            string testCname = clientCert.Subject;

            CertRequest clientCertRequest = createCertRequest(testCname, clientCertEmail, rootCert.GetSerialNumberString());
            keyController.Add(clientCertRequest);

            // Assert the record exists in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Get the record from the DB
            Certificate certDbEntry = db.Certificates.Single();
            string pin = db.spSelectUserDecryptPIN(clientCertEmail).First();
            Assert.IsNotNull(certDbEntry.PrivateKeyEncryption);
            Assert.IsNotNull(pin);
            X509Certificate2 expectedCert = new X509Certificate2(certDbEntry.PrivateKeyEncryption, pin, X509KeyStorageFlags.Exportable);

            // Assert that the data we get back for a valid request matches our clientCert
            HttpResponseMessage keyMessage = keyController.GetKeysByEmail(clientCertEmail);
            Assert.AreNotEqual(new HttpResponseMessage(), keyMessage);
            Assert.IsNotNull(keyMessage.Content);

            string expectedKeyString = expectedCert.GetCertHashString();
            X509Certificate2 certFromController = new X509Certificate2(keyMessage.Content.ReadAsByteArrayAsync().Result);
            string keyStringFromController = certFromController.GetCertHashString();

            Assert.AreEqual(expectedKeyString, keyStringFromController);

            // Assert we throw an HttpResponseException for an invalid email
            Assert.Throws<HttpResponseException>(delegate
            {
                HttpResponseMessage invalidKeyMessage = keyController.GetKeysByEmail("E=badEmail@test.com");
            });
        }

        /// <summary>
        /// The put function issues a new certificate, keeping only the PIN and private keys.
        /// In this function, we assert that the PIN and pirvate key of the default clientCert
        /// is equal to the new clientCert that we create through the Put function.
        /// </summary>
        [Test]
        public void testPut()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            string testCname = clientCert.Subject;

            CertRequest clientCertRequest = createCertRequest(clientCertName, clientCertEmail, rootCert.GetSerialNumberString());
            keyController.Add(clientCertRequest);

            // Assert the record exists in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Capture the string representation of the current tlsCert:
            CaModel.certDBEntities newDbContext = new certDBEntities();
            Certificate clientCertDbEntry = newDbContext.Certificates.Single();

            // Update key with a PUT request
            keyController.Put(clientCertRequest);

            // Assert that we still have only one entry in the DB
            Assert.AreEqual(1, db.Certificates.Count());

            // Capture thye PIN, Private key, and string representation of the re-issued tlsCert
            CaModel.certDBEntities updatedDbContext = new certDBEntities();
            Certificate newClientCertDbEntry = updatedDbContext.Certificates.Single();

            Assert.IsNotNull(newClientCertDbEntry.LastEcryptionPIN);
            Assert.IsNotNull(newClientCertDbEntry.LastPrivateKeyEncryption);
            Assert.AreNotEqual(clientCertDbEntry.EncryptionCertExpDate, newClientCertDbEntry.EncryptionCertExpDate);
            Assert.AreNotEqual(clientCertDbEntry.SigningCertExpDate, newClientCertDbEntry.SigningCertExpDate);
            Assert.AreNotEqual(clientCertDbEntry.DateModified, newClientCertDbEntry.DateModified);
        }

        [Test]
        public void testDelete()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            string testCname = clientCert.Subject;
            string signingCertName = rootCert.GetSerialNumberString();

            CertRequest clientCertRequest = createCertRequest(testCname, clientCertEmail, signingCertName);
            keyController.Add(clientCertRequest);

            // Assert the record exists in the database
            Assert.AreEqual(1, db.Certificates.Count());

            // Attempt to delete record for the DB, and assert we have no data left
            keyController.Delete(clientCertEmail, signingCertName);
            Assert.AreEqual(0, db.Certificates.Count());
        }

        private CertRequest createCertRequest(string cname, string email, string signingCertName)
        {
            CertRequest certRequest = new CertRequest();
            certRequest.cname = cname;
            certRequest.email = email;
            certRequest.signingCertName = signingCertName;

            return certRequest;
        }
    }
}