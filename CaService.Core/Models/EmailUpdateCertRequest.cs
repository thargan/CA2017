using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public class EmailUpdateCertRequest : UpdateCertRequestBase, IEmailCert,  ICaServiceModel
    {
        public string Email { get; set; }
        public string NameTitle { get; set; }
        public string NameFirst { get; set; }
        public string NameLast { get; set; }

        [EnumDataType(typeof(AccountType))]
        public AccountType AccountType { get; set; }


        
    }
}