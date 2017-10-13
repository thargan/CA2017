namespace Ses.CaService.Data
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Certificate")]
    public partial class Certificate
    {
        public int Id { get; set; }

        public int? PracticeId { get; set; }

        [StringLength(100)]
        public string EmailAS1 { get; set; }

        [StringLength(50)]
        public string PIN { get; set; }

        public byte[] EncryptedPIN { get; set; }

        public byte[] PublicKeyEncryption { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? EncryptionCertExpDate { get; set; }

        public byte[] PublicKeySigning { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? SigningCertExpDate { get; set; }

        public byte[] PrivateKeyEncryption { get; set; }

        public byte[] PrivateKeySigning { get; set; }

        [StringLength(50)]
        public string EncryptionPIN { get; set; }

        [StringLength(50)]
        public string SigningPIN { get; set; }

        public byte[] LastPrivateKeyEncryption { get; set; }

        [StringLength(50)]
        public string LastEcryptionPIN { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? LastCertReplaceDate { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateCreated { get; set; }

        [StringLength(50)]
        public string CreatedBy { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? DateModified { get; set; }

        [StringLength(50)]
        public string ModifiedBy { get; set; }

        [StringLength(150)]
        public string ProfileName { get; set; }

        public bool? IsExternal { get; set; }

        public bool? IsDeleted { get; set; }
    }
}
