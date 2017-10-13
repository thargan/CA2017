using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public class TlsCreateCertRequest : CreateCertRequestBase
    {
        /// <summary>
        /// CN
        /// </summary>
        [Required(ErrorMessage = "OrganizationName is required")]
        public string OrganizationName { get; set; }

        /// <summary>
        /// O
        /// </summary>
        [Required(ErrorMessage = "OrgId is required")]
        public string OrgId { get; set; }

        /// <summary>
        /// OU = VendorId
        /// </summary>
        /// 
        [Required(ErrorMessage = "VendorId is required")]
        public string VendorId { get; set; }

        public new int DefaultTimeToLiveInMonths = 36;
        //in case a client sends a csr
        //public  string CSR = null;
        //public  string[] CSRARRAY = null;
        public  byte[] CSRBYTEARRAY = null;
    }
}