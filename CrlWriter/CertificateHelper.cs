using Ses.CaService.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CrlWriter
{
    internal class CertificateHelper
    {
        internal CaServiceDbContext db =  new CaServiceDbContext();
        
        //internal X509Certificate2 RetrieveEmailCertificate(string email, bool isDelete)
        //{
        //    Certificate certificate = null;
        //    certificate = db.Certificates.Where(e => e.EmailAS1 == email).FirstOrDefault();

        //    if (null == certificate)
        //    {
        //        throw new ApplicationException("Email certificate not found --> " + email);
        //    }
        //    byte[] rawData = null;
        //    X509Certificate2 x509Certificate = null;
        //    if (isDelete)
        //    {
        //        rawData = certificate.PrivateKeyEncryption.ToArray();
        //        x509Certificate = new X509Certificate2(rawData, certificate.PIN, X509KeyStorageFlags.Exportable);
        //    }
        //    else
        //    {
        //        rawData = certificate.LastPrivateKeyEncryption.ToArray();
        //        x509Certificate = new X509Certificate2(rawData, certificate.LastEcryptionPIN, X509KeyStorageFlags.Exportable);
        //    }
        //    return x509Certificate;
        //}

        internal void DeleteEmailCertificate(string email)
        {
            Certificate dbRecord = db.Certificates.Where(e => e.EmailAS1 == email && e.IsDeleted == true).FirstOrDefault();
            if (dbRecord != null)
            {
                db.Certificates.Remove(dbRecord);
                db.SaveChanges();
            }
        }

        //internal X509Certificate2 RetrieveTlsCertificate(string orgId)
        //{
        //    TlsCertificate certificate = db.TlsCertificates.Where(e => e.OrgId == orgId).FirstOrDefault();
        //    if (null == certificate)
        //    {
        //        throw new ApplicationException("TLS certificate not found --> " + orgId);
        //    }
        //    byte[] rawData = certificate.PrivateKeyEncryption.ToArray();
        //    X509Certificate2 x509Certificate = new X509Certificate2(rawData, certificate.PIN, X509KeyStorageFlags.Exportable);

        //    return x509Certificate;
        //}

        internal void DeleteTlsCertificate(string orgId)
        {
            TlsCertificate dbRecord = db.TlsCertificates.Where(e => e.OrgId == orgId).FirstOrDefault();
            db.TlsCertificates.Remove(dbRecord);
            db.SaveChanges();
        }

        internal X509Certificate2 RetrieveSigningCertificate(string x509SerialNumber)
        {
            X509Certificate2 signingCert = null;
            X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            x509Store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCollection = (X509Certificate2Collection)x509Store.Certificates;

            foreach (X509Certificate2 x509 in storeCollection)
            {
                if (x509.SerialNumber == x509SerialNumber)
                {
                    signingCert = x509;
                    break;
                }
            }

            //if(signingCert.HasPrivateKey && signingCert.PrivateKey.)

            if(null == signingCert)
            {
                throw new ApplicationException("Signing certificate not found --> Serial Number: " + x509SerialNumber);
            }

            return signingCert;
        }
    }
}
