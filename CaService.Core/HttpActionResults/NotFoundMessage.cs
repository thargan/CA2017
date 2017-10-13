using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace Ses.CaService.Core
{
    public class TextHttpActionResult : IHttpActionResult
    {
        public TextHttpActionResult(string text, HttpRequestMessage request)
        {
            if (text == null)
            {
                throw new ArgumentNullException("text");
            }
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            Text = text;
            Request = request;
        }

        public string Text { get; private set; }

        public HttpRequestMessage Request { get; private set; }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        public HttpResponseMessage Execute()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.NotFound);
            response.Content = new StringContent(Text); // Put the text in the response body (text/plain content).
            response.RequestMessage = Request;
            return response;
        }
    }

    public static class ApiControllerExtensions
    {
        public static TextHttpActionResult NotFound(this ApiController controller, string text)
        {
            return new TextHttpActionResult(text, controller.Request);
        }

        public static TextHttpActionResult Conflict(this ApiController controller, string text)
        {
            return new TextHttpActionResult(text, controller.Request);
        }
    }
}