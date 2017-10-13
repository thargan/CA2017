using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public class EmailCreateCertRequest : CreateCertRequestBase, IEmailCert,  ICaServiceModel
    {
        public string OrganizationName { get; set; }

        public string NameTitle { get; set; }

        public string NameFirst { get; set; }

        public string NameLast { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "A valid email address is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "AccountType is required")]
        [EnumDataType(typeof(AccountType))]
        public AccountType AccountType { get; set; }
    }
}