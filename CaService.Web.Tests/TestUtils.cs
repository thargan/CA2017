using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Controllers;
using Ses.CaService.Core;
using Ses.CaService.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Hosting;
using System.Web.Http.Results;
using System.Web.Http.Routing;

namespace CaService.Web.Tests
{
    public class TestUtils
    {
        internal void MockHttpRequest(EmailCertsController controller, HttpMethod httpMethod, HttpRouteData routeData, string url)
        {
            var config = new HttpConfiguration();
            var request = new HttpRequestMessage(httpMethod, url);
            controller.ControllerContext = new HttpControllerContext(config, routeData, request);
            controller.Request = request;
            controller.Request.Properties[HttpPropertyKeys.HttpConfigurationKey] = config;
        }
    }

   public class TestUtils<T, U> where T : ApiController where U : ICaServiceModel
    {
        internal void MockHttpRequest(T controller, U model, HttpMethod httpMethod, HttpRouteData routeData, string url)
        {
            var config = new HttpConfiguration();
            var request = new HttpRequestMessage(httpMethod, url);
            controller.ControllerContext = new HttpControllerContext(config, routeData, request);
            controller.Request = request;
            controller.Request.Properties[HttpPropertyKeys.HttpConfigurationKey] = config;
            controller.Validate<U>(model);
        }

        internal void AssertEncryptionAndSigningKeyPairsAreNotEqual(CreatedNegotiatedContentResult<EmailCertResponse> result)
        {
            KeyPair encryptionKeyPair = null;
            KeyPair signingKeyPair = null;
            var keyPairs = result.Content.KeyPairs;
            foreach (var kp in keyPairs)
            {
                if (kp.Type == KeyPairType.Encryption)
                    encryptionKeyPair = kp;
                else if (kp.Type == KeyPairType.Signing)
                    signingKeyPair = kp;
            }
            Assert.IsNotNull(encryptionKeyPair);
            Assert.IsNotNull(signingKeyPair);
            Assert.AreNotEqual(encryptionKeyPair.SerialNumber, signingKeyPair.SerialNumber);
        }    
    }
}
