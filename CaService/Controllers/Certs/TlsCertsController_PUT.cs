using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel.DataAnnotations;
using CERTENROLLLib;
using Ses.CaService.Data;
using Ses.CaService.Core.Models;
using Ses.CaService.Crypto;
using Newtonsoft.Json;
using Ses.CaService.Core.Crypto;

namespace Ses.CaService.Controllers
{
    public partial class TlsCertsController : BaseController
    {
        /// <summary>
        /// Update X509 certificate
        /// </summary>
        [Route("{orgId}")]
        [Route("{orgId}/renew")]
        [Route("{orgId}/reissue")]
        [HttpPut]
        public IHttpActionResult Update(string orgId, TlsUpdateCertRequest model)
        {
            if (null == model) model = new TlsUpdateCertRequest();
            if (!ModelState.IsValid) return BadModel(orgId);

            ParseRoute(orgId, model);
            if (!CertificateInDb(orgId)) return CertNotExist(orgId);

            string data = JsonConvert.SerializeObject(model);
            _log.Debug("> ModelState.IsValid --> " + data);

            try
            {
                TlsCertificate certificate = FetchCertificateFromDb(orgId);
                string profileName = String.IsNullOrEmpty(model.CertProfileName) ? certificate.ProfileName : model.CertProfileName;
                CertificateProfile cp = FetchCertificateProfileFromDb(profileName);                
                if (null == cp) return CertProfileNotFound(orgId, certificate.ProfileName);

                _log.Debug("> Certificate profile: " + profileName);

                string sn = cp.SigningCertSerialNumber;
                X509Certificate2 x509SigningCert = RetrieveSigningCert(sn);
                if (null == x509SigningCert) return SigningCertNotFound(orgId, sn);

                _log.Debug("> Signing certificate: " + cp.SigningCertSerialNumber);
                
                X509Certificate2 x509CertToUpdate;
                string pin = RetrievePin(orgId);
                x509CertToUpdate = RetrieveX509Certificate(orgId, pin);
                if (null == x509CertToUpdate) { return CertNotExist(orgId); }

                X509Certificate2 x509UpdatedCert = null;
                CX500DistinguishedName dn = new CX500DistinguishedName();
                dn.Encode(x509CertToUpdate.SubjectName.Name, X500NameFlags.XCN_CERT_NAME_STR_NONE);
                DateTime expirationDate = DateTime.Now.AddMonths(model.TimeToLiveInMonths);
                string password = String.Empty;
                string ekuOidString = cp.EnhancedKeyUsageOID;
                string[] ekuOid = ekuOidString.Split(';');

                if (model.IsReissue)
                {   // REISSUE...
                    if (AnyAreNotNull(model.OrganizationName, model.VendorId, model.City, model.State))
                    {                        
                        if (AllAreNotNull(model.OrganizationName, model.VendorId, model.City, model.State, model.Country))
                        {
                            //dn = ClientCertManager.CreateOrganizationDn(model.OrganizationName, orgId, model.VendorId, model.City, model.State, model.Country);
                            dn = DnBuilder.CreateTlsDn(new DnFields()
                                {
                                    CN = model.OrganizationName,
                                    O = orgId,
                                    OU = model.VendorId,
                                    L = model.City,
                                    S = model.State,
                                    C = model.Country
                                });
                        }
                        else
                        {
                            return BadRequest("To update DN all of the following properties are required: OrganizationName, VendorId, City, State.");
                        }
                    }

                    x509UpdatedCert = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION_SIGNING, 
                        dn, x509SigningCert, expirationDate, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
                    );
                    _log.Info(_route + " --> Created reissue certificate with Serial Number: " + x509UpdatedCert.SerialNumber);

                    UpdateTlsCertInDB(x509UpdatedCert, orgId, true); // true=reissue
                    RevokeCertificate(x509CertToUpdate, x509SigningCert.SerialNumber, null, orgId);
                }
                else
                {   // RENEW...
                    var signingCert = new X509Certificate2(); // TO DO: get signing cert from CP DB

                    x509UpdatedCert = ccm.RenewCert(x509CertToUpdate, signingCert, expirationDate, cp.CRLURL, cp.AIAPath);
                    if (x509CertToUpdate.SerialNumber.CompareTo(x509UpdatedCert.SerialNumber) != 0)
                    {
                        return SerialNumberMismatch(x509CertToUpdate, x509UpdatedCert);
                    }
                    _log.Info(_route + " --> Created renew certificate with Serial Number: " + x509UpdatedCert.SerialNumber);

                    UpdateTlsCertInDB(x509UpdatedCert, orgId, false);  // false=renew
                }

                var response = BuildTlsCertResponse(orgId, cp, x509UpdatedCert, true); // isPut=true

                return Created<TlsCertResponse>(response.Href, response); 
            }
            catch (Exception e)
            {
                string message = "TLS Cert Update Failure --> Exception thrown: " + orgId;
                _log.Error(message, e);

                return  InternalServerError(new ApplicationException(message, e));
            }
        }

        private IHttpActionResult SerialNumberMismatch(X509Certificate2 certToUpdate, X509Certificate2 updatedCert)
        {
            string message = string.Format("TLS Cert Renew Failure --> Serial number mismatch: {0} != {1}", certToUpdate.SerialNumber, updatedCert.SerialNumber);

            throw new ApplicationException(message);
        }

        private IHttpActionResult BadModel(string orgId)
        {
            _log.Info("PUT api/v2/certs/tls/" + orgId + " --> " + ModelState.ToString());

            return BadRequest(ModelState);
        }

        private IHttpActionResult ModelNotFound(string orgId)
        {
            string message = "TLS Cert Update Failure --> UpdateTlsCertRequest object not found";
            _log.Info("PUT api/v2/certs/tls/" + orgId + " ---> " + message);

            return BadRequest(message);
        }

        private void ParseRoute(string orgId, UpdateCertRequestBase model)
        {
            string route = Request.GetRouteData().Route.RouteTemplate;

            if (route.Contains("renew")) model.IsReissue = false;
            else if (route.Contains("reissue")) model.IsReissue = true;

            _route = "PUT api/v2/certs/tls/" + orgId + "/" + (model.IsReissue ? "reissue" : "renew");
            _log.Info(_route);
        }

        private IHttpActionResult DbUpdateFailure(string orgId)
        {
            string message = _route + " >> TLS Cert Update Failure --> DB Update failure: " + orgId;
            _log.Warn(message);

            throw new ApplicationException(message);
        }

        private bool UpdateTlsCertInDB(X509Certificate2 updatedCert, string orgId, bool reissue = true)
        {
            TlsCertificate dbRecord = FetchCertificateFromDb(orgId);
            string oldPin = RetrievePin(orgId);

            string pin = reissue ? GeneratePin() : oldPin;
            dbRecord.PIN = pin;

            byte[] pfx = updatedCert.Export(X509ContentType.Pfx, pin);
            dbRecord.PrivateKeyEncryption = pfx;
            dbRecord.PrivateKeySigning = pfx;

            dbRecord.DateModified = DateTime.Now;
            dbRecord.ModifiedBy = reissue ? "CA Service - Reissue" : "CA Service - Renew";
            db.SaveChanges();
            _log.Debug("> Updated in DB: " + DatabaseName);

            return true;
        }
    }
}