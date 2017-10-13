namespace Ses.CaService.Data
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Audit")]
    public partial class Audit
    {
        public int Id { get; set; }

        public int? CertificaterRowId { get; set; }

        public int? ActorId { get; set; }

        [Column(TypeName = "datetime2")]
        public DateTime? ActionDate { get; set; }

        [StringLength(50)]
        public string ActionDescription { get; set; }
    }
}
