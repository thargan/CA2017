using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Ses.CaService.Core.Models
{
    public class CrlRevokeMessage
    {
        public X509Certificate2 Certificate { get; set; }

        public string CertSerialNumber { get; set; }

        public string SigningCertSerialNumber { get; set; }

        public bool IsDelete { get; set; }  
        
        // EMAIL CERT ONLY
        public string EmailAddress { get; set; }
        
        // TLS CERT ONLY
        public string OrgId { get; set; }

    
    }
}