using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public class TlsUpdateCertRequest : UpdateCertRequestBase
    {
        public string VendorId { get; set; }
    }
}