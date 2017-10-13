using System;
using System.Data.Entity;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Data.Entity.Core.Objects;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.Core.Metadata.Edm;
using CodeFirstStoreFunctions;
using System.Data.SqlClient;
using System.Data;

namespace Ses.CaService.Data
{
    public partial class CaServiceDbContext : DbContext
    {
        public CaServiceDbContext() : base("name=CaServiceDbContext")
        {
            Database.SetInitializer(new CaServiceDbContextInitializer());
        }

        private string _connectionString = System.Configuration.ConfigurationManager.ConnectionStrings["CaServiceDbContext"].ConnectionString;
        
        public virtual DbSet<Audit> Audits { get; set; }
        public virtual DbSet<Certificate> Certificates { get; set; }
        public virtual DbSet<CertificateProfile> CertificateProfiles { get; set; }
        public virtual DbSet<TlsCertificate> TlsCertificates { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Conventions.Add(new FunctionsConvention<CaServiceDbContext>("dbo"));

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.ProfileName)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.SigningCertSerialNumber)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.CRLURL)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.AIAPath)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.CertPolicyOID)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.LOAPolicyOID)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.CategoryOID)
                .IsUnicode(false);

            modelBuilder.Entity<CertificateProfile>()
                .Property(e => e.EnhancedKeyUsageOID)
                .IsUnicode(false);

            modelBuilder.Entity<TlsCertificate>()
                .Property(e => e.VendorId)
                .IsUnicode(false);

            modelBuilder.Entity<TlsCertificate>()
                .Property(e => e.OrganizationName)
                .IsUnicode(false);

            modelBuilder.Entity<TlsCertificate>()
                .Property(e => e.OrgId)
                .IsFixedLength();
        }

        public class CaServiceDbContextInitializer : CreateDatabaseIfNotExists<CaServiceDbContext>
        {
            public override void InitializeDatabase(CaServiceDbContext context)
            {
                base.InitializeDatabase(context);
                /*
                context.Database.ExecuteSqlCommand( ...create tables... );
                */
            }
        }
    }
}
