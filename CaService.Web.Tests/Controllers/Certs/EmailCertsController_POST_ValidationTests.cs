using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Controllers;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;
using System.Web.Http;
using System.Net.Http;
using System.Diagnostics;
using System.Web.Http.Results;
using Ses.CaService.Core.Crypto;
using System.Net;
using System.Web.Http.Routing;

namespace CaService.Web.Tests
{
    [TestClass]
    public class EmailCertsController_POST_ValidationTests : EmailCertsController_TestsBase
    {
        [TestMethod]
        public void NameFirst_IsNull__Create_Patient__Returns_BadRequestErrorMessageResult()
        {
            var route = Controller.Configuration.Routes.MapHttpRoute("TestRoute", "api/v2/certs/email");
            var routeData = new HttpRouteData(route);

            var model = PatientModel_POST;
            model.Email = "invalid-" + model.Email;
            model.NameFirst = null;

            Utils_POST.MockHttpRequest(Controller, model, HttpMethod.Post, routeData, TestData.URL_POST);

            // Act
            IHttpActionResult contentResult = Controller.Create(model);

            if (contentResult is BadRequestErrorMessageResult)
            {
                var errorMessageResult = contentResult as BadRequestErrorMessageResult;
                Assert.AreEqual(errorMessageResult.Message, "NameFirst is required.");
            }
            else
                Assert.Fail();
        }

        [TestMethod]
        public void NameLast_IsNull__Create_Patient__Returns_BadRequestErrorMessageResult()
        {
            var route = Controller.Configuration.Routes.MapHttpRoute("TestRoute", "api/v2/certs/email");
            var routeData = new HttpRouteData(route);

            var model = PatientModel_POST;
            model.Email = "invalid-" + model.Email;
            model.NameLast = null;

            Utils_POST.MockHttpRequest(Controller, model, HttpMethod.Post, routeData, TestData.URL_POST);

            // Act
            IHttpActionResult contentResult = Controller.Create(model);

            if (contentResult is BadRequestErrorMessageResult)
            {
                var errorMessageResult = contentResult as BadRequestErrorMessageResult;
                Assert.AreEqual(errorMessageResult.Message, "NameLast is required.");
            }
            else
                Assert.Fail();
        }
    }
}
