namespace Ses.CaService.Data
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("CertificateProfile")]
    public partial class CertificateProfile
    {
        public int Id { get; set; }

        [StringLength(150)]
        public string ProfileName { get; set; }

        [StringLength(150)]
        public string SigningCertSerialNumber { get; set; }

        [StringLength(150)]
        public string CRLURL { get; set; }

        [StringLength(150)]
        public string AIAPath { get; set; }

        [StringLength(150)]
        public string CertPolicyOID { get; set; }

        [StringLength(150)]
        public string LOAPolicyOID { get; set; }

        [StringLength(150)]
        public string CategoryOID { get; set; }

        [StringLength(300)]
        public string EnhancedKeyUsageOID { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateCreated { get; set; }

        [StringLength(50)]
        public string CreatedBy { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateModified { get; set; }

        [StringLength(50)]
        public string ModifiedBy { get; set; }
    }
}
