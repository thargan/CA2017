using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Controllers;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;
using System.Web.Http;
using System.Net.Http;
using System.Diagnostics;
using System.Web.Http.Results;
using System.Collections.Generic;
using System.Web.Http.Routing;

namespace CaService.Web.Tests
{
    [TestClass]
    public class EmailCertsController_POST_IntegrationTests : EmailCertsController_TestsBase
    {
        [TestMethod]       
        public void Create_Professional__Returns_EmailCertResponse()
        {
            var model = ProfessionalModel_POST;
            var route = Controller.Configuration.Routes.MapHttpRoute("TestRoute", "api/v2/certs/email");
            var routeData = new HttpRouteData(route);
            Utils_POST.MockHttpRequest(Controller, model, HttpMethod.Post, routeData, TestData.URL_POST);

            IHttpActionResult contentResult = Controller.Create(model);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;
                string resultSubject = result.Content.Subject;
                string professionalSubject = GetTestSubject(AccountType.Professional, model);
                Assert.AreEqual(professionalSubject, resultSubject);

                Utils_POST.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);

                TestData.TestCerts.Add(new KeyValuePair<AccountType, string>(AccountType.Professional, result.Content.EmailAddress));
            }
            else
                Assert.Fail("Result is not CreatedNegotiatedContentResult<EmailCertResponse>");
        }

        [TestMethod]
        public void Create_Patient__Returns_EmailCertResponse()
        {
            var model = PatientModel_POST;
            var route = Controller.Configuration.Routes.MapHttpRoute("TestRoute", "api/v2/certs/email");
            var routeData = new HttpRouteData(route);
            Utils_POST.MockHttpRequest(Controller, model, HttpMethod.Post, routeData, TestData.URL_POST);
            
            IHttpActionResult contentResult = Controller.Create(model);

            if (contentResult is CreatedNegotiatedContentResult<EmailCertResponse>)
            {
                var result = contentResult as CreatedNegotiatedContentResult<EmailCertResponse>;

                string resultSubject = result.Content.Subject;
                string patientSubject = GetTestSubject(AccountType.Patient, model);
                Assert.AreEqual(patientSubject, resultSubject);

                Utils_POST.AssertEncryptionAndSigningKeyPairsAreNotEqual(result);

                TestData.TestCerts.Add(new KeyValuePair<AccountType, string>(AccountType.Patient, result.Content.EmailAddress));
            }
            else
                Assert.Fail("Result is not CreatedNegotiatedContentResult<EmailCertResponse>");
        }
    }
}
