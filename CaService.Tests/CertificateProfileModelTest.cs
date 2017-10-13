using NUnit.Framework;
using Ses.CaModel;
using Ses.CaService.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CaServiceTests
{
    [TestFixture]
    class CertificateProfileModelTest
    {
        private CaModel.certDBEntities db = new certDBEntities();
        private string profileName = "UnitTest Profile Name";

        [SetUp]
        public void SetUp() { }

        [TearDown]
        public void TearDown()
        {
            db.CertificateProfiles.RemoveRange(db.CertificateProfiles.Where(e => e.ProfileName.Contains("unittest")));
            db.SaveChanges();
        }

        [Test]
        public void TestCreate()
        {
            string crlurl = "http://testcrl.net/crl.crl";
            string aiaPath = "/path/to/test/AIA";
            string certPolicyOID = "0.0.0.0.0.0";
            string loaPolicyOID = "1.1.1.1.1.1";
            string ekuOID = "2.2.2.2.2.2";
            string signingCertSerial = "533E17B88FEB479B415DE47184B7F056";

            int initialCount = db.CertificateProfiles.Count();
            addToDb(profileName, crlurl, aiaPath, certPolicyOID, loaPolicyOID, ekuOID);
            Assert.AreEqual(initialCount + 1, db.CertificateProfiles.Count());
            CertificateProfile dbRecord = db.CertificateProfiles.Where(e => e.ProfileName == profileName).First();

            Assert.AreEqual(profileName, dbRecord.ProfileName);
            Assert.AreEqual(crlurl, dbRecord.CRLURL);
            Assert.AreEqual(aiaPath, dbRecord.AIAPath);
            Assert.AreEqual(certPolicyOID, dbRecord.CertPolicyOID);
            Assert.AreEqual(loaPolicyOID, dbRecord.LOAPolicyOID);
            Assert.AreEqual(ekuOID, dbRecord.EnhancedKeyUsageOID);
            Assert.AreEqual(signingCertSerial, dbRecord.SigningCertSerialNumber);
        }

        private CertificateProfile addToDb(string profileName = "UnitTest Profile Name", string crlurl= "http://testcrl.net/crl.crl", string aiaPath = "/path/to/test/AIA", string certPolicyOID = "0.0.0.0.0.0", string loaPolicyOID = "1.1.1.1.1.1", string ekuOID = "2.2.2.2.2.2,3.3.3.3.3.3", string signingCertSerial = "533E17B88FEB479B415DE47184B7F056")
        {
            DateTime createdDate = DateTime.Now;
            CertificateProfile newProfile = new CertificateProfile()
            {
                ProfileName = profileName,
                CRLURL = crlurl,
                SigningCertSerialNumber = signingCertSerial,
                AIAPath = aiaPath,
                CertPolicyOID = certPolicyOID,
                LOAPolicyOID = loaPolicyOID,
                EnhancedKeyUsageOID = ekuOID,
                DateCreated = createdDate
            };
            db.CertificateProfiles.Add(newProfile);
            db.SaveChanges();
            return newProfile;
        }

        [Test]
        public void TestGetById()
        {
            int initialCount = db.CertificateProfiles.Count();
            CertificateProfile expectedProfile = addToDb();
            Assert.AreEqual(initialCount + 1, db.CertificateProfiles.Count());

            BaseController bc = new BaseController();
            CertificateProfile testProfile = bc.GetCertificateProfileFromDB(expectedProfile.Id);

            Assert.AreEqual(expectedProfile.ProfileName, testProfile.ProfileName);
            Assert.AreEqual(expectedProfile.CRLURL, testProfile.CRLURL);
            Assert.AreEqual(expectedProfile.AIAPath, testProfile.AIAPath);
            Assert.AreEqual(expectedProfile.CertPolicyOID, testProfile.CertPolicyOID);
            Assert.AreEqual(expectedProfile.LOAPolicyOID, testProfile.LOAPolicyOID);
            Assert.AreEqual(expectedProfile.EnhancedKeyUsageOID, testProfile.EnhancedKeyUsageOID);
            Assert.AreEqual(expectedProfile.DateCreated, testProfile.DateCreated);
            Assert.AreEqual(expectedProfile.SigningCertSerialNumber, testProfile.SigningCertSerialNumber);
        }

        [Test]
        public void TestGetByName()
        {
            int initialCount = db.CertificateProfiles.Count();
            CertificateProfile expectedProfile = addToDb();
            Assert.AreEqual(initialCount + 1, db.CertificateProfiles.Count());

            BaseController bc = new BaseController();
            CertificateProfile testProfile = db.CertificateProfiles.Where(e => e.ProfileName == expectedProfile.ProfileName).FirstOrDefault();

            Assert.AreEqual(expectedProfile.ProfileName, testProfile.ProfileName);
            Assert.AreEqual(expectedProfile.CRLURL, testProfile.CRLURL);
            Assert.AreEqual(expectedProfile.AIAPath, testProfile.AIAPath);
            Assert.AreEqual(expectedProfile.CertPolicyOID, testProfile.CertPolicyOID);
            Assert.AreEqual(expectedProfile.LOAPolicyOID, testProfile.LOAPolicyOID);
            Assert.AreEqual(expectedProfile.EnhancedKeyUsageOID, testProfile.EnhancedKeyUsageOID);
            Assert.AreEqual(expectedProfile.DateCreated, testProfile.DateCreated);
            Assert.AreEqual(expectedProfile.SigningCertSerialNumber, testProfile.SigningCertSerialNumber);

        }
    }
}
