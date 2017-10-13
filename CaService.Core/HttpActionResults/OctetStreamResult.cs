using System;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Web.Http;

namespace Ses.CaService.Core
{
    public class OctetStreamResult : IHttpActionResult
    {
        private readonly byte[] _content;
        private readonly string _filename;

        public OctetStreamResult(byte[] content, string filename = "")
        {
            if (content == null) throw new ArgumentNullException("content");
            _content = content;
            _filename = filename;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(_content)
                };

                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                if (_filename.Length > 0)
                {
                    var disposition = new ContentDispositionHeaderValue("attachment");
                    disposition.FileName = _filename;
                    response.Content.Headers.ContentDisposition = disposition;
                }
                return response;

            }, cancellationToken);
        }
    }
}