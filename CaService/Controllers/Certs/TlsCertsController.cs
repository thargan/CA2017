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

namespace Ses.CaService.Controllers
{
    [RoutePrefix("api/v2/certs/tls")]
    public partial class TlsCertsController : BaseController
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(TlsCertsController));
        //private static readonly string _baseUri = @"api/v2/certs/tls";

        
        private TlsCertificate _certificate;
        protected TlsCertificate Certificate
        {
            get
            {
                if (null == _certificate)
                {
                    _log.Info(_route + " --> Fetching from DB: " + _key);
                    _certificate = db.TlsCertificates.Where(x => x.OrgId == _key && x.IsDeleted!=true).FirstOrDefault();
                    
                }
                return _certificate;
            }
        }

        #region PRIVATE METHODS
        private IHttpActionResult CertNotFound(string orgId, string kind = "")
        {
            kind = String.IsNullOrWhiteSpace(kind) ? string.Empty : kind + " ";
            string message = String.Format(_route + " > TLS Cert Retrieve {0}Failure --> Not Found: {1}", kind, orgId);
            _log.Warn(message);

            return NotFound(message);
        }

        private IHttpActionResult HandleException(string orgId, Exception e)
        {
            string message = "TLS Cert Failure --> Exception thrown: " + orgId;
            _log.Error(message, e);

            return InternalServerError(new ApplicationException(message, e));
        }

        private TlsCertResponse BuildTlsCertResponse(string orgId, CertificateProfile certProfile, X509Certificate2 x509, Boolean isPut = false)
        {
            var response = new TlsCertResponse();

            response.Href = Request.RequestUri + (isPut ? String.Empty : "/" + orgId);
            response.Href = response.Href.ToLower();
            response.Href = response.Href.Replace("/reissue", "").Replace("/renew", "");

            response.OrgId = orgId;
            response.CertProfileName = certProfile.ProfileName;
            
            response.ExpirationDate = x509.GetExpirationDateString();
            response.EffectiveDate = x509.GetEffectiveDateString();
            response.KeyPairs.Add(new KeyPair(KeyPairType.TLS)
            {
                SerialNumber = x509.SerialNumber,
                Thumbprint = x509.Thumbprint
            });
            response.Subject = x509.Subject;
            response.Issuer.Subject = x509.Issuer;

            return response;
        }

        private byte[] RetrievePrivateKey(string orgId, string pin = "")
        {
            X509Certificate2 tlsCert = RetrieveX509Certificate(orgId);
            if (null == tlsCert) { return null; }
            string PIN = pin ?? RetrievePin(orgId);

            return tlsCert.Export(X509ContentType.Pfx, PIN);
        }

        private X509Certificate2 RetrieveX509Certificate(string orgId, string pin = "")
        {
            _log.Debug("> Retrieving x509 Cert");

            TlsCertificate certificate = FetchCertificateFromDb(orgId);
            if (null == certificate) return null;

            string PIN = String.IsNullOrWhiteSpace(pin) ? RetrievePin(orgId) : pin;
            byte[] rawPfx = certificate.PrivateKeyEncryption.ToArray();
            X509Certificate2 x509Certificate = new X509Certificate2(rawPfx, PIN, X509KeyStorageFlags.Exportable);

            return x509Certificate;
        }

        private byte[] RetrievePfx(string orgId)
        {
            _log.Debug("> Retrieving PFX");

            string PIN = RetrievePin(orgId);
            X509Certificate2 cert = RetrieveX509Certificate(orgId, PIN);
            if (null == cert) return null;

            return cert.Export(X509ContentType.Pfx, PIN);
        }

        private byte[] RetrievePublicKey(string orgId)
        {
            _log.Debug("> Retrieving Public Key");

            string PIN = RetrievePin(orgId);
            if (null == PIN) return null; 

            if (String.Equals(PIN,"PUBLIC-KEY-ONLY"))  
            {
                return(RetrieveCSRCert(orgId));
            }
             
            X509Certificate2 cert = RetrieveX509Certificate(orgId, PIN);
            if (null == cert) return null;

            return cert.Export(X509ContentType.Cert, PIN);
        }

        //Retrieve the csr cert
        private byte[] RetrieveCSRCert(string orgId)
        {
            _log.Debug("> Retrieving CSR Cert from DB");  

            TlsCertificate certificate = FetchCertificateFromDb(orgId);

            if (null == certificate) return null;
            
            byte[] rawCert = certificate.PrivateKeyEncryption.ToArray();
            X509Certificate2 cert = new X509Certificate2(rawCert);  
            if (null == cert) return null; 
             return cert.Export(X509ContentType.Cert);
        }



        private TlsCertificate FetchCertificateFromDb(string orgId)
        {
            _key = orgId;

            return Certificate;
        }

        private string RetrievePin(string orgId)
        {
            _log.Debug("> Retrieving PIN");

            _key = orgId;
            string PIN = Certificate.PIN;

            return PIN;
        }

        private bool CertificateInDb(string orgId)
        {
            _key = orgId;
            return null != Certificate;
        }
        #endregion
    }
}