using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Description;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel.DataAnnotations;
using Ses.CaService.Data;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;

namespace Ses.CaService.Controllers
{
    public partial class EmailCertsController : BaseController
    {
        /// <summary>
        /// Delete / Revoke X509 certificate
        /// </summary>
        [Route("{email}")]
        [HttpDelete]
        public IHttpActionResult Delete(string email)
        {
            _route = string.Format("DELETE api/v2/certs/{0}",email);
            _log.Info(_route);
            try
            {
                if (!CertificateInDb(email))
                    return CertNotExist(email);

                if (CheckForSoftDelete(email))
                    return CertNotExist(email);



                DeleteEmailCertificate(email);

                InvalidateCacheEntries(email);

                return Ok("Deleted email certificate: " + email);
            }
            catch (Exception e)
            {
                string message = "Email Cert Delete Failure --> Exception thrown: " + email;
                _log.Error(message, e);

                return InternalServerError(new ApplicationException(message, e));
            }
        }

        /// <summary>
        /// Delete / Revoke X509 certificate
        /// </summary>
        //[Route("{email}")]
        [Route("{email}/revoke")]
        [HttpDelete]
        public IHttpActionResult DeleteRevoke(string email)
        {
            _route = string.Format("DELETE api/v2/certs/{0}/revoke", email);
            _log.Info(_route);
            try
            {
                if (!CertificateInDb(email)) return CertNotExist(email);

                Certificate certificate = FetchCertificateFromDb(email);
                CertificateProfile certProfileName = FetchCertificateProfileFromDb(certificate.ProfileName);
                if (null == certProfileName) CertProfileNotFound(email, certificate.ProfileName);

                _log.Debug("> Found CertProfileName: " + certProfileName);

                string sn = certProfileName.SigningCertSerialNumber;
                X509Certificate2 signingCert = new X509Certificate2();
                signingCert = RetrieveSigningCert(sn);
                if (null == signingCert) SigningCertNotFound(email, sn);

                _log.Debug("> Signing Certificate: " + signingCert.SerialNumber);

                X509Certificate2 encryptionX509;
                X509Certificate2 signingX509;

                string pin = RetrievePin(email);

                encryptionX509 = RetrieveX509Certificate(email, KeyPairType.Encryption, pin);
                RevokeCertificate(encryptionX509, signingCert.SerialNumber, email, null, true);
                _log.Info(_route + " -->  Key pair queued for revocation with Serial Number: " + encryptionX509.SerialNumber + " --> " + KeyPairType.Encryption.ToString());

                signingX509 = RetrieveX509Certificate(email, KeyPairType.Signing, pin);

                if (encryptionX509.GetSerialNumber() != signingX509.GetSerialNumber())
                {
                    RevokeCertificate(signingX509, signingCert.SerialNumber, email, null, true);
                    _log.Info(_route + " --> Key pair queued for revocation with Serial Number: " + signingX509.SerialNumber + " --> " + KeyPairType.Signing.ToString());
                }

                SoftDeleteCertFromDb(email);
                _log.Info(_route + " --> Soft-deleted in DB: " + DatabaseName);

                InvalidateCacheEntries(email);

                return Ok("Deleted email certificate: " + email);
            }
            catch (Exception e)
            {
                string message = "Email Cert Delete Failure --> Exception thrown: " + email;
                _log.Error(message, e);

                return InternalServerError(new ApplicationException(message, e));
            }
        }

        private bool CheckForSoftDelete(string email)
        {
            return db.Certificates.Any(e => e.EmailAS1 == email && e.IsDeleted == true);
        }

        private void SoftDeleteCertFromDb(string email)
        {   
            Certificate dbRecord = db.Certificates.Where(e => e.EmailAS1 == email).FirstOrDefault();
            dbRecord.IsDeleted = true;
            dbRecord.ModifiedBy = "CA Service - Revoke";
            dbRecord.DateModified = DateTime.Now;
            db.SaveChanges();
        }

        private void DeleteEmailCertificate(string email)
        {
            Certificate dbRecord = db.Certificates.Where(e => e.EmailAS1 == email).FirstOrDefault();
            db.Certificates.Remove(dbRecord);
            db.SaveChanges();
        }
    }


}