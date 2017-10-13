using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Controllers;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;
using System.Web.Http;
using System.Web.Http.Routing;
using System.Net.Http;
using System.Diagnostics;
using System.Web.Http.Results;
using Ses.CaService.Core.Crypto;

namespace CaService.Web.Tests
{
    [TestClass]
    public class EmailCertsController_DELETE_Tests : EmailCertsController_TestsBase
    {
        [TestMethod]
        public void Revoke_Professional__Returns_EmailCertResponse()
        {
            /*
            var originalPrivateKeyEncryption = Certificate.PrivateKeyEncryption;
            var originalPrivateKeySigning = Certificate.PrivateKeySigning;
            */
            LoadTestCertificate(AccountType.Professional);
            Utils_DELETE.MockHttpRequest(Controller, HttpMethod.Delete,
                GetRouteData("api/v2/certs/email/{email}"),
                String.Format(TestData.URL_PUT_REISSUE, Certificate.EmailAS1));

            IHttpActionResult contentResult = Controller.Delete(Certificate.EmailAS1);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;                 

                Utils_PUT.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);
            }
            else if(contentResult is OkNegotiatedContentResult<string>)
            {
                ;
            }
            else
                Assert.Fail();
        }

        [Ignore]
        [TestMethod]
        public void Revoke_Patient__Returns_EmailCertResponse()
        {
            var model = PatientModel_PUT;

            if (TestData.TestCerts.Count > 0)
                model.Email = TestData.GetTestCert(AccountType.Patient);
            else
                model.Email = LoadTestCertificate(AccountType.Patient).EmailAS1;

            var originalPrivateKeyEncryption = Certificate.PrivateKeyEncryption;
            var originalPrivateKeySigning = Certificate.PrivateKeySigning;

            model.TimeToLiveInMonths = 36;

            Utils_PUT.MockHttpRequest(Controller, model, HttpMethod.Put,
                GetRouteData("api/v2/certs/email/{email}/reissue"),
                String.Format(TestData.URL_PUT_REISSUE, model.Email));

            IHttpActionResult contentResult = Controller.Update(model.Email, model);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;

                string resultSubject = result.Content.Subject;
                string patientSubject = GetTestSubject(AccountType.Patient, model);
                Assert.AreEqual(patientSubject, resultSubject);

                // TTL == 36 months
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) > DateTime.Now.AddMonths(36).Subtract(new TimeSpan(24, 0, 0)));
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) < DateTime.Now.AddMonths(36).AddDays(1));

                // Old Key Pair vs. New Key Pair => not the same!
                var reissued = RetrieveCertificateFromDB(Certificate.EmailAS1);
                Assert.AreNotEqual<byte[]>(originalPrivateKeyEncryption, reissued.PrivateKeyEncryption);
                Assert.AreNotEqual<byte[]>(originalPrivateKeySigning, reissued.PrivateKeySigning);

                Utils_PUT.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);
            }
            else
                Assert.Fail();
        }

        [Ignore]
        [TestMethod]
        public void Revoke_Professional2__Returns_EmailCertResponse()
        {
            var model = ProfessionalModel_PUT;

            if (TestData.TestCerts.Count > 0)
                model.Email = TestData.GetTestCert(AccountType.Professional);
            else
                model.Email = LoadTestCertificate(AccountType.Professional).EmailAS1;

            Utils_PUT.MockHttpRequest(Controller, model, HttpMethod.Put,
                GetRouteData("api/v2/certs/email/{email}/renew"),
                String.Format(TestData.URL_PUT_RENEW, model.Email));
                        
            IHttpActionResult contentResult = Controller.Update(model.Email, model);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;

                // TTL == 12 months
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) > DateTime.Now.AddMonths(12).Subtract(new TimeSpan(24, 0, 0)));
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) < DateTime.Now.AddMonths(12).AddDays(1));

                string resultSubject = result.Content.Subject;
                string professionalSubject = GetTestSubject(AccountType.Professional, model);
                Assert.AreEqual(professionalSubject, resultSubject);

                Utils_PUT.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);
            }
            else
                Assert.Fail("contentResult is " + contentResult.GetType().ToString());
        }

        [Ignore]
        [TestMethod]
        public void Revoke_Patient2__Returns_EmailCertResponse()
        {
            var model = PatientModel_PUT;

            if (TestData.TestCerts.Count > 0)
                model.Email = TestData.GetTestCert(AccountType.Patient);
            else
                model.Email = LoadTestCertificate(AccountType.Patient).EmailAS1;

            model.TimeToLiveInMonths = 24;


            Utils_PUT.MockHttpRequest(Controller, model, HttpMethod.Put,
                GetRouteData("api/v2/certs/email/{email}/renew"),
                String.Format(TestData.URL_PUT_RENEW, model.Email));
            
            IHttpActionResult contentResult = Controller.Update(model.Email, model);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;

                // TTL == 24 months
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) > DateTime.Now.AddMonths(24).Subtract(new TimeSpan(24, 0, 0)));
                Assert.IsTrue(DateTime.Parse(result.Content.ExpirationDate) < DateTime.Now.AddMonths(24).AddDays(1));

                // validate DN
                string resultSubject = result.Content.Subject;
                string patientSubject = GetTestSubject(AccountType.Patient, model);
                Assert.AreEqual(patientSubject, resultSubject);

                Utils_PUT.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);
            }
            else
                Assert.Fail();
        }
    }
}
