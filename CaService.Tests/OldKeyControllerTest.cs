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
using System.Web.Http;

namespace Ses.CaServiceTests
{
    /// <summary>
    /// This class tests the functions in the OldKeyController class.
    /// If the tests are failing when first adding this code to your local machine, please check the following:
    ///
    /// 1. Ensure that everybody has Full Control of the root certificate created by these unit tests:
    ///     1a. Run 'mmc'
    ///     1b. File -> Add/Remove snap-in
    ///     1c. Add "Certificates" to the list
    ///     1d. Locate certificates by navigating to Certificates(Local Computer) -> Personal -> Certificates
    ///     1e. Right-click on rootTestCert -> All Tasks -> Manage Pirvate Keys
    ///     1f. Click "Add...", type "Everyone", press "Check names", hit OK
    /// 2. Ensure that the "spInsertUserEncryptPin" stored procedure exists on your local machine's SQL server
    /// 3. Ensure that "CreateKeys.sql" stored procedure has been run (CaService/CaService/App_Data)
    /// </summary>
    [TestFixture]
    public class OldKeyControllerTest
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(OldKeyControllerTest));

        private KeyController keyController = new KeyController();
        private OldKeyController oldKeyController = new OldKeyController();
        private CaModel.certDBEntities db = new certDBEntities();

        //private AriCertManager certManager = new AriCertManager();
        private RootCertManager rootCertManager = new RootCertManager();

        private ClientCertManager clientCertManager = new ClientCertManager();

        private X509Certificate2 rootCert;
        private X509Certificate2 clientCert;
        private DateTime expirationDate = DateTime.Now.AddYears(1);

        private string rootCertName = "oldKeyRootTestCert";
        private string rootCertEmail = "oldKeyRootTestCert@test.com";
        private string clientCertName = "clientTestCert";
        private string clientCertEmail = "test@test.com";

        private X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        [SetUp]
        public void KeyControllerTestSetup()
        {
            log4net.Config.XmlConfigurator.Configure();

            // Remove all records in the database and flush the cache
            db.Certificates.RemoveRange(db.Certificates);
            db.SaveChanges();
            ElastiCacheClient ecc = ElastiCacheClientFactory.GetClient();
            ecc.Flush();

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
        }

        [TearDown]
        public void KeyControllerTestTearDown()
        {
            // DB entries are not deleted in TearDown because if the test fails, entries are left
            // in the DB if we have DB. We instead clear the DB before each run in SetUp
            BaseCertManager.RemoveCertFromStore(clientCertName);
            BaseCertManager.RemoveCertFromStore(rootCertName);
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
            CaModel.certDBEntities originalDbContext = new certDBEntities();
            Certificate originalCertDbEntry = originalDbContext.Certificates.Single();

            // Update the record in the database so that we have an old key
            keyController.Put(clientCertRequest);
            CaModel.certDBEntities newDbContext = new certDBEntities();
            Assert.AreEqual(1, newDbContext.Certificates.Count());

            // Get a response from the oldKeyController and see if the data equals what's in the DB
            HttpResponseMessage oldKeyMessage = oldKeyController.GetKeysByEmail(clientCertEmail);
            byte[] oldKey = oldKeyMessage.Content.ReadAsByteArrayAsync().Result;
            X509Certificate2 oldKeyCert = new X509Certificate2(oldKey);

            // Get the latest record from the DB
            Certificate newCertDbEntry = newDbContext.Certificates.Single();
            Assert.AreNotEqual(originalCertDbEntry, newCertDbEntry);
            Assert.IsNotNull(newCertDbEntry.LastPrivateKeyEncryption);
            X509Certificate2 expectedCert = new X509Certificate2(newCertDbEntry.LastPrivateKeyEncryption.ToArray(), newCertDbEntry.LastEcryptionPIN.Trim(), X509KeyStorageFlags.Exportable);

            Assert.AreEqual(expectedCert.GetCertHashString(), oldKeyCert.GetCertHashString());

            // Finally, assert we throw an HttpResponseException for an invalid email
            Assert.Throws<HttpResponseException>(delegate
            {
                HttpResponseMessage invalidKeyMessage = oldKeyController.GetKeysByEmail("E=badEmail@test.com");
            });
        }

        [Test]
        public void testGetKeysByEmailNoOldKeys()
        {
            // First, assert that we have no record (because DB should be empty)
            Assert.AreEqual(0, db.Certificates.Count());

            // Insert a client tlsCert record into the DB:
            string testCname = clientCert.Subject;

            CertRequest clientCertRequest = createCertRequest(testCname, clientCertEmail, rootCert.GetSerialNumberString());
            keyController.Add(clientCertRequest);

            // Assert the record exists in the database
            Assert.AreEqual(1, db.Certificates.Count());
            CaModel.certDBEntities originalDbContext = new certDBEntities();
            Certificate originalCertDbEntry = originalDbContext.Certificates.Single();

            // Do NOT update the record, and assert that an exception is thrown when we fetch an invalid key
            Assert.Throws<HttpResponseException>(delegate
            {
                HttpResponseMessage oldKeyMessage = oldKeyController.GetKeysByEmail(clientCertEmail);
                byte[] oldKey = oldKeyMessage.Content.ReadAsByteArrayAsync().Result;
                X509Certificate2 oldKeyCert = new X509Certificate2(oldKey);
                Assert.IsNull(oldKeyCert.GetCertHashString());
            });
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