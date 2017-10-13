using System.Web.Http;
using System.Net.Http.Formatting;

namespace Ses.CaService
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Formatters.Add(new BsonMediaTypeFormatter());

            // NOTE: Routes are declared as attributes above functions
            // This enables us to have versioned APIs with multiple public functions in controllers, and be selective about what we expose
        }
    }
}