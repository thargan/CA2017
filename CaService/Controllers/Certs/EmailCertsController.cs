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
using Ses.CaService.Core.Queuing;
using Ses.CaService.Core.Crypto;

namespace Ses.CaService.Controllers
{
    [RoutePrefix("api/v2/certs/email")]
    public partial class EmailCertsController : BaseController
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(EmailCertsController));
        private static readonly string _baseUri = @"api/v2/certs/email";

        private Certificate _certificate;
        protected Certificate Certificate
        {
            get
            {
                if (null == _certificate)
                {
                    _log.Info(_route + " --> Fetching from DB: " + _key);
                    _certificate = db.Certificates.Where(e => e.EmailAS1 == _key).FirstOrDefault();
                }
                return _certificate;
            }
        }



        #region PRIVATE METHODS
        private IHttpActionResult CertNotFound(string email, string kind = "")
        {
            kind = String.IsNullOrWhiteSpace(kind) ? string.Empty : kind + " ";
            string message = String.Format(_route + " >> Email Cert Retrieve {0}Failure --> Not Found: {1}", kind, email);
            _log.Warn(message);

            return NotFound(message);
        }

        private IHttpActionResult HandleException(string email, Exception e)
        {
            string message = "Email Cert Failure --> Exception thrown: " + email;
            _log.Error(message, e);

            return InternalServerError(new ApplicationException(message, e));
        }

        private EmailCertResponse BuildEmailCertResponse(string email, CertificateProfile certProfile, X509Certificate2 encryptionCert, X509Certificate2 signingCert = null, Boolean isPut = false)
        {
            var response = new EmailCertResponse();
            
            response.Href = Request.RequestUri + (isPut ? String.Empty : "/" + email);
            response.Href = response.Href.ToLower();
            response.Href = response.Href.Replace("/reissue", "").Replace("/renew", "");

            response.EmailAddress = email;
            response.CertProfileName = (null != certProfile ? certProfile.ProfileName : String.Empty);

            response.ExpirationDate = encryptionCert.GetExpirationDateString();
            response.EffectiveDate = encryptionCert.GetEffectiveDateString();

            response.Subject = encryptionCert.Subject;
            response.CrlUrl = GetCrlUrl(certProfile, encryptionCert);
            response.AiaPath = GetAiaPath(certProfile, encryptionCert);

            response.KeyPairs.Add(new KeyPair(KeyPairType.Encryption)
                {
                    SerialNumber = encryptionCert.SerialNumber,
                    Thumbprint = encryptionCert.Thumbprint
                });

            if (null != signingCert)
            {
                response.KeyPairs.Add(new KeyPair(KeyPairType.Signing)
                {
                    SerialNumber = signingCert.SerialNumber,
                    Thumbprint = signingCert.Thumbprint
                });
            }

            response.Issuer.Subject = encryptionCert.Issuer;
            
            var issuerSerialNumber = RetrieveIssuingCertificateSerialNumber(encryptionCert.Issuer);
            if (!String.IsNullOrWhiteSpace(issuerSerialNumber))
                response.Issuer.SerialNumber = issuerSerialNumber;

            return response;
        }

        private string RetrieveIssuingCertificateSerialNumber(string x509CertIssuer)
        {
            X509Certificate2 x509Cert = Utils.RetrieveIssuingCertificate(x509CertIssuer);
            if(null == x509Cert || null == x509Cert.SerialNumber)
                return String.Empty;
            else
                return x509Cert.SerialNumber;
        }


        private bool FlushAllCache()
        {
            bool cacheFlush=CacheFlush();
            if (cacheFlush)
            {
                _log.Debug("> Cache Flushed " );
            }else{
            
                _log.Debug("> Cache could not be Flushed ");
            
             }
            return cacheFlush;
        }
		
         private bool InvalidateCacheEntries(string email)
        {
            bool cacheDelete=CacheDelete(Config.emailCertPrefix + email);
            if (cacheDelete)
            {
                _log.Debug("> Cache cleared: " + email);
            }else{
            
                _log.Debug("> Cache could not be cleared for : " + email);
            
             }
            return cacheDelete;
        }

        private byte[] RetrievePublicKey(string email, KeyPairType keyPairType)
        {
            _log.Debug("> Retrieving Public Key");

            string PIN = RetrievePin(email);
            if (null == PIN) return null;

            X509Certificate2 cert = RetrieveX509Certificate(email, keyPairType, PIN);
            if (null == cert) return null;

            return cert.Export(X509ContentType.Cert, PIN);
        }

        private byte[] RetrievePfxWithBlankPassword(string email, KeyPairType keyPairType)
        {
            _log.Debug("> Retrieving PFX with blank password: " + keyPairType.ToString());

            X509Certificate2 emailCert = RetrieveX509Certificate(email, keyPairType);
            if (null == emailCert) return null;

            return emailCert.Export(X509ContentType.Pfx, "");
        }

        private byte[] RetrievePfx(string email, KeyPairType keyPairType)
        {
            _log.Debug("> Retrieving PFX");

            string PIN = RetrievePin(email);
            if (null == PIN) return null;

            X509Certificate2 cert = RetrieveX509Certificate(email, keyPairType, PIN);
            if (null == cert) return null;

            return cert.Export(X509ContentType.Pfx, PIN);
        }

        private byte[] RetrievePriorPfxWithBlankPassword(string email)
        {
            _log.Debug("> Retrieving Prior PFX with blank password");

            Certificate certificate = FetchCertificateFromDb(email);
            string PIN = certificate.LastEcryptionPIN;
            if (string.IsNullOrEmpty(PIN)) return null;

            byte[] rawPfx = certificate.LastPrivateKeyEncryption.ToArray();
            X509Certificate2 priorCert = new X509Certificate2(rawPfx, PIN, X509KeyStorageFlags.Exportable);
            if (null == priorCert) return null;

            return priorCert.Export(X509ContentType.Pfx, "");
        }

        private IHttpActionResult CertNotExist(string email)
        {
            string message = "Email Cert Failure --> Certificate does not exist: " + email;
            _log.Info(message);

            return NotFound(message);
        }

        private X509Certificate2 RetrieveX509Certificate(string email, KeyPairType keyPairType, string pin = "")
        {
            _log.Debug("> Retrieving x509 Cert");

            Certificate certificate = FetchCertificateFromDb(email);
            if (null == certificate) return null;

            string PIN = String.IsNullOrWhiteSpace(pin) ? RetrievePin(email) : pin;
            byte[] rawPfx = null;

            if(keyPairType==KeyPairType.Encryption)
                rawPfx = certificate.PrivateKeyEncryption.ToArray();
            else
                rawPfx = certificate.PrivateKeySigning.ToArray();

            X509Certificate2 x509Certificate = new X509Certificate2(rawPfx, PIN, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            return x509Certificate;
        }

        private Certificate FetchCertificateFromDb(string email)
        {
            _key = email;

            return Certificate;
        }

        private string RetrievePin(string email)
        {
            _log.Debug("> Retrieving PIN");

            _key = email;
            string PIN = Certificate.PIN;

            return PIN;
        }

        private bool CertificateInDb(string email)
        {
            bool retval;
            _log.Info(_route + " --> Checking certificate existence in DB: " + email);
            try
            {
                using (CaServiceDbContext db = new CaServiceDbContext())
                {
                    retval = db.Certificates.Any(e => e.EmailAS1 == email);
                    return retval;
                }
            }
            catch (Exception ex)
            {
                _log.Error(string.Format("Error checking certificate existence: {0} --> Exception thrown: {1}", email, ex));
                throw;
            }
        }
        #endregion
    }
}