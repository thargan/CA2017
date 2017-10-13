using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using System.Web.Http;
using System.Net.Http;
using System.Net;
using Ses.CaService.Core.Models;


namespace Ses.CaService.Core
{
    [AttributeUsage(AttributeTargets.Method)]
    public class CheckNameFirstAndNameLastAttribute : ActionFilterAttribute
    {
        public static T GetPropertyValue<T>(object obj, string propertyName)
        {
            if (null == obj) return default(T);
            var property = obj.GetType().GetProperty(propertyName);
            var value = property.GetValue(obj);
            if (null == value) return default(T);
            return (T)value;
        }

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            string firstName = String.Empty;
            string lastName = String.Empty;
            string errorMessage = String.Empty;

            var args = actionContext.ActionArguments;
            foreach(var kvp in args)
            {
                if(kvp.Key == "model")
                {
                    firstName = GetPropertyValue<string>(kvp.Value, "NameFirst");
                    lastName = GetPropertyValue<string>(kvp.Value, "NameFirst");
                    break;
                }
            }

            if (!String.IsNullOrWhiteSpace(firstName) || !String.IsNullOrWhiteSpace(lastName))
            {
                if (String.IsNullOrWhiteSpace(firstName) || String.IsNullOrWhiteSpace(lastName))
                {
                    if (String.IsNullOrWhiteSpace(firstName))
                    {
                        errorMessage = "NameFirst is required when NameLast is not null.";
                    }
                    else // lastName
                    {
                        errorMessage = "NameLast is required when NameFirst is not null.";
                    }
                    HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.BadRequest);
                    response.Content = new StringContent(errorMessage);
                    response.RequestMessage = actionContext.Request;
                    actionContext.Response = response;
                }
            }
        }
    }
}
