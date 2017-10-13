using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Models
{
    public interface IEmailCert
    {
         string Email { get; set; }
         string NameTitle { get; set; }
         string NameFirst { get; set; }
         string NameLast { get; set; }
         string OrganizationName { get; set; }
         string Country { get; set; }
         string City { get; set; }
         string State { get; set; }
         int TimeToLiveInMonths { get; set; }
         string CertProfileName { get; set; }
         AccountType AccountType { get; set; }
    }
}
