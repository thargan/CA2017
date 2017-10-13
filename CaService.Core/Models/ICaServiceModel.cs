using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Models
{
    public interface ICaServiceModel
    {
        string NameFirst { get; set; }
        string NameLast { get; set; }
        string Email { get; set; }
        string City { get; set; }
        string State { get; set; }
        string Country { get; set; }
        string OrganizationName { get; set; }
    }
}
