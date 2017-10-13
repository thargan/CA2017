using System;
using System.Web.Http;
using System.Web.Http.Description;
using System.Security.Cryptography.X509Certificates;
using Ses.CaService.Data;
using Ses.CaService.Core;
using Ses.CaService.Core.Models;

namespace Ses.CaService.Controllers
{
    public partial class EmailCertsController : BaseController
    {
        /// <summary>
        /// Retrieve public encryption key 
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult Get(string email)
        {
            _route = String.Format("GET {0}/{1}", _baseUri, email);
            _log.Info(_route);

            try
            {
                byte[] publicKey = null;
                publicKey = CacheGet(Config.emailCertPrefix + email);
                if (publicKey == null)
                {
                    if (!CertificateInDb(email)) return CertNotFound(email);

                    publicKey = RetrievePublicKey(email, KeyPairType.Encryption);
                    if (publicKey == null) return CertNotFound(email);

                    CacheSet(Config.emailCertPrefix + email, publicKey);
                    _log.Info(_route + " --> Public encryption key pushed to cache: " + email);
                }
                else
                {
                    _log.Info(_route + " --> Public encryption key pulled from cache: " + email);
                }

                return new OctetStreamResult(publicKey, email + ".cer");
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }

        /// <summary>
        /// Validate existence of x509 certificate
        /// </summary>
        /// <param name="email">Email Address</param>
        /// <returns>true if email cert found</returns>
        [Route("{email}/exists")]
        [HttpGet]
        [ResponseType(typeof(Boolean))]
        public IHttpActionResult Exists(string email)
        {
            _route = String.Format("GET {0}/{1}/exists", _baseUri, email);
            _log.Info(_route);

            try
            {
                var cert = CacheGet(Config.emailCertPrefix + email);
                if (null != cert) return Ok(true);

                if (CertificateInDb(email)) return Ok("true");
                else return NotFound("false");
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }

        /// <summary>
        /// Retrieve pin
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/pin")]
        [HttpGet]
        [ResponseType(typeof(String))]
        public IHttpActionResult GetPin(string email)
        {
            _route = String.Format("GET {0}/{1}/pin", _baseUri, email);
            _log.Info(_route);

            try
            {
                if (!CertificateInDb(email)) return CertNotFound(email, "Pin");

                string pin = RetrievePin(email);
                if (pin == null) return CertNotFound(email, "Pin");

                return Ok(pin);
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }

        /// <summary>
        /// Retrieve PFX with encryption key pair
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/key")]
        [Route("{email}/encryption")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult GetEncryptionPfxWithBlankPassword(string email)
        {
            _route = String.Format("GET {0}/{1}/key", _baseUri, email);
            _log.Info(_route);

            try
            {
                byte[] key = null;

                if (!CertificateInDb(email)) return CertNotFound(email, "Key");

                key = RetrievePfxWithBlankPassword(email, KeyPairType.Encryption);
                if (key == null) return CertNotFound(email, "Key");

                return new OctetStreamResult(key);
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }
        /// <summary>
        /// Retrieve PFX with signing key pair
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/signing")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult GetSigningPfxWithBlankPassword(string email)
        {
            _route = String.Format("GET {0}/{1}/key", _baseUri, email);
            _log.Info(_route);

            try
            {
                byte[] key = null;

                if (!CertificateInDb(email)) return CertNotFound(email, "Key");

                key = RetrievePfxWithBlankPassword(email, KeyPairType.Signing);
                if (key == null) return CertNotFound(email, "Key");

                return new OctetStreamResult(key);
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }

        /// <summary>
        /// Retrieve prior encryption key pair
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/key/prior")]
        [Route("{email}/encryption/prior")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult GetPriorEncryptionKeyPair(string email)
        {
            _route = String.Format("GET {0}/{1}/key/prior", _baseUri, email);
            _log.Info(_route);        

            try
            {
                if (!CertificateInDb(email)) return CertNotFound(email, "Prior Key");

                byte[] pfx = null;
                pfx = RetrievePriorPfxWithBlankPassword(email);
                if (pfx == null) return CertNotFound(email, "Prior Key");

                return new OctetStreamResult(pfx);
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }

        /// <summary>
        /// Retrieve PFX file with encryption key pair
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/pfx")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult RetrieveEncryptionKeyPairPfxFile(string email)
        {
            _route = String.Format("GET {0}/{1}/pfx", _baseUri, email);
            _log.Info(_route); 

            try
            {
                if (!CertificateInDb(email)) return CertNotFound(email, "PFX");

                byte[] pfx = null;
                pfx = RetrievePfx(email, KeyPairType.Encryption);
                if (pfx == null) return CertNotFound(email, "PFX");

                return new OctetStreamResult(pfx, email + ".pfx");
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }
    }
}