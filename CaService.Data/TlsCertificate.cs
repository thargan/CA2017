namespace Ses.CaService.Data
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("TLSCertificate")]
    public partial class TlsCertificate
    {
        public int Id { get; set; }

        [StringLength(150)]
        public string VendorId { get; set; }

        [StringLength(150)]
        public string OrganizationName { get; set; }

        [StringLength(50)]
        public string PIN { get; set; }

        public byte[] PrivateKeyEncryption { get; set; }

        public byte[] PrivateKeySigning { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateCreated { get; set; }

        [StringLength(50)]
        public string CreatedBy { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateModified { get; set; }

        [StringLength(50)]
        public string ModifiedBy { get; set; }

        [StringLength(50)]
        public string OrgId { get; set; }

        [StringLength(150)]
        public string ProfileName { get; set; }

        public bool? IsDeleted { get; set; }
    }
}
