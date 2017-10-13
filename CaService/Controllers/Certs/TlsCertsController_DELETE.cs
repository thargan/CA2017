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

namespace Ses.CaService.Controllers
{
    public partial class TlsCertsController : BaseController
    {
        /// <summary>
        /// Revoke X509 certificate
        /// </summary>
        [Route("{orgId}")]
        [Route("{orgId}/revoke")]
        [HttpDelete]
        public IHttpActionResult Delete(string orgId)
        {
            _route = "DELETE api/v2/certs/tls/" + orgId;
            _log.Info(_route);
            if (!CertificateInDb(orgId)) return CertNotExist(orgId);

            try
            {
                TlsCertificate certificate = FetchCertificateFromDb(orgId);

                CertificateProfile certProfileName = FetchCertificateProfileFromDb(certificate.ProfileName);
                if (null == certProfileName) return CertProfileNotFound(orgId, certificate.ProfileName);
                _log.Debug("> Found CertProfileName: " + certProfileName.ProfileName);

                string sn = certProfileName.SigningCertSerialNumber;
                X509Certificate2 signingCert = new X509Certificate2();               
                signingCert = RetrieveSigningCert(sn);
                if (null == signingCert) return SigningCertNotFound(orgId, sn);

                _log.Debug("> Signing Certificate: " + signingCert.SerialNumber);
                
                X509Certificate2 certToRevoke;         
                string pin = RetrievePin(orgId);
                if (String.Equals(pin,"PUBLIC-KEY-ONLY"))  
                {
                      byte[] rawCert = certificate.PrivateKeyEncryption.ToArray();
                      certToRevoke = new X509Certificate2(rawCert);
                }
                else
                {
                    certToRevoke = RetrieveX509Certificate(orgId, pin);
                } 
                RevokeCertificate(certToRevoke, signingCert.SerialNumber, null, orgId, true);
                SoftDeleteCertFromDb(orgId);

                return Ok("Deleted TLS certificate: " + orgId);
            }
            catch (Exception e)
            {
                string message = "TLS Cert Delete Failure --> Exception thrown: " + orgId;
                _log.Error(message, e);

                return InternalServerError(new ApplicationException(message, e));
            }
        }

        private IHttpActionResult CertNotExist(string orgId)
        {
            string message = "TLS Cert Failure --> Certificate does not exist: " + orgId;
            _log.Info(message);

            return NotFound(message);
        }

        private bool SoftDeleteCertFromDb(string orgId)
        {
            TlsCertificate dbRecord = db.TlsCertificates.Where(e => e.OrgId == orgId).FirstOrDefault();
            dbRecord.IsDeleted = true;
            dbRecord.ModifiedBy = "CA Service - Revoke";
            dbRecord.DateModified = DateTime.Now;
            db.SaveChanges();
            _log.Info(_route + " --> Soft-deleted in DB: " + DatabaseName);

            return true;
        }
    }
}