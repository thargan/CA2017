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
    public partial class TlsCertsController : BaseController
    {        
        /// <summary>
        /// Retrieve public key 
        /// </summary>
        /// <param name="orgId">OrgID</param>
        [Route("{orgId}")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult Get(string orgId)
        {
            _route = "GET api/v2/certs/tls/" + orgId;
            _log.Info(_route);

            try
            {
                byte[] publicKey = null;

                if (!CertificateInDb(orgId)) return CertNotFound(orgId);

                publicKey = RetrievePublicKey(orgId);
                if (publicKey == null)
                {
                    return CertNotFound(orgId);
                }                    

                return new OctetStreamResult(publicKey, orgId + ".cer");
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }



           /// </summary>
        /// <param name="orgId">OrgID</param>
        [Route("csrcert/{orgId}")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult GetCSRCert(string orgId)
        {
            _route = "GET api/v2/certs/tls/csrcert/" + orgId;
            _log.Info(_route);

            try
            {
                byte[] publicKey = null;

                if (!CertificateInDb(orgId)) return CertNotFound(orgId);

                publicKey = RetrieveCSRCert(orgId);
                if (publicKey == null)
                {
                    return CertNotFound(orgId);
                }                    

                return new OctetStreamResult(publicKey, orgId + ".cer");
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }
		

        /// <summary>
        /// Validate existence of x509 certificate
        /// </summary>
        /// <param name="orgId">OrgID</param>
        /// <returns>true if orgId cert found</returns>
        [Route("{orgId}/exists")]
        [HttpGet]
        [ResponseType(typeof(Boolean))]
        public IHttpActionResult Exists(string orgId)
        {
            _route = "GET api/v2/certs/tls/" + orgId + "/exists";
            _log.Info(_route);

            try
            {
                var cert = CacheGet(Config.tlsCertPrefix + orgId);
                if (null != cert)
                {
                    return Ok(true);
                }

                if (CertificateInDb(orgId))
                {
                    return Ok("true");
                }
                else
                {
                    return NotFound("false");
                }
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }

        /// <summary>
        /// Retrieve pin
        /// </summary>
        /// <param name="orgId">orgId Address</param>
        [Route("{orgId}/pin")]
        [HttpGet]
        [ResponseType(typeof(String))]
        public IHttpActionResult GetPin(string orgId)
        {
            _route = "GET api/v2/certs/tls/" + orgId + "/pin";
            _log.Info(_route);

            try
            {
                if (!CertificateInDb(orgId)) return CertNotFound(orgId, "pin");

                string pin = RetrievePin(orgId);
                if (pin == null)
                {
                    return CertNotFound(orgId, "pin");
                }
                return Ok(pin);
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }

        /// <summary>
        /// Retrieve private key
        /// </summary>
        /// <param name="orgId">OrgID</param>
        [Route("{orgId}/key")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult RetrieveKey(string orgId)
        {
            _route = "GET api/v2/certs/tls/" + orgId + "/key";
            _log.Info(_route);

            try
            {
                byte[] key = null;

                if (!CertificateInDb(orgId)) return CertNotFound(orgId, "key");

                key = RetrievePrivateKey(orgId);
                if (key == null)
                {
                    return CertNotFound(orgId, "pin");
                }

                return new OctetStreamResult(key);
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }

        /// <summary>
        /// Retrieve PFX file
        /// </summary>
        /// <param name="orgId">OrgID</param>
        /// <returns></returns>
        [Route("{orgId}/pfx")]
        [HttpGet]
        [ResponseType(typeof(OctetStreamResult))]
        public IHttpActionResult RetrievePfxFile(string orgId)
        {
            _route = "GET api/v2/certs/tls/" + orgId + "/pfx";
            _log.Info(_route);

            try
            {
                if (!CertificateInDb(orgId)) return CertNotFound(orgId, "PFX");

                byte[] pfx = null;
                pfx = RetrievePfx(orgId);
                if (pfx == null)
                {
                    return CertNotFound(orgId, "PFX");
                }
                return new OctetStreamResult(pfx, orgId + ".pfx");
            }
            catch (Exception e)
            {
                return HandleException(orgId, e);
            }
        }
    }
}