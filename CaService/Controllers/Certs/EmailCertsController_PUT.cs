using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel.DataAnnotations;
using Ses.CaService.Data;
using Ses.CaService.Core.Models;
using Ses.CaService.Crypto;
using Ses.CaService.Core;
using Newtonsoft.Json;
using Ses.CaService.Core.Crypto;
using System.Net;

namespace Ses.CaService.Controllers
{
    public partial class EmailCertsController : BaseController
    {
        /// <summary>
        /// Update X509 certificate
        /// </summary>
        [Route("{email}")]
        [Route("{email}/renew")]
        [Route("{email}/reissue")]
        [Route("{email}/keyspec")]
        [CheckNameFirstAndNameLast()]
        [HttpPut]
        public IHttpActionResult Update(string email, EmailUpdateCertRequest model)
        {
            if (null == model) model = new EmailUpdateCertRequest();
            if (!ModelState.IsValid) return BadModel(email);

            X509Certificate2 encryptionKeyPairToUpdate = null, signingKeyPairToUpdate = null, 
                encryptionCertificate = null, signingCertificate = null;

            ParseRoute(email, model);
            try
            {

                if (!CertificateInDb(email)) return CertNotExist(email);

                string data = JsonConvert.SerializeObject(model);
                _log.Debug("> ModelState.IsValid... " + data);

                CertificateProfile certificateProfile = GetCertificateProfile(model);
                DateTime expirationDate = DateTime.Now.AddMonths(model.TimeToLiveInMonths);

                encryptionKeyPairToUpdate = RetrieveX509Certificate(email, KeyPairType.Encryption);
                signingKeyPairToUpdate = RetrieveX509Certificate(email, KeyPairType.Signing);

                if (model.IsReissue)
                {
                    var validationResult = ValidateModelForReissue(email, model);
                    if (null != validationResult) return validationResult;

                    ReissueCert(email, model, certificateProfile, expirationDate, ref encryptionKeyPairToUpdate, ref signingKeyPairToUpdate);
                    encryptionCertificate = encryptionKeyPairToUpdate;
                    signingCertificate = signingKeyPairToUpdate;
                }
                else if (model.IsUpdateKeyspec)
                {
                    encryptionCertificate = UpdateCertKeySpec(email, encryptionKeyPairToUpdate, KeyPairType.Encryption);
                    signingCertificate = UpdateCertKeySpec(email, signingKeyPairToUpdate, KeyPairType.Signing);
                }
                else
                {
                    encryptionCertificate = RenewCert(email, certificateProfile, encryptionKeyPairToUpdate, expirationDate, KeyPairType.Encryption);
                    signingCertificate = RenewCert(email, certificateProfile, signingKeyPairToUpdate, expirationDate, KeyPairType.Signing);
                }
               
                	bool cahceInvalidationSuccessful=InvalidateCacheEntries(email);
                for (int i = 0; i <2; i++) {
                    if (!cahceInvalidationSuccessful) { 
                         cahceInvalidationSuccessful=InvalidateCacheEntries(email); 
                    }
                    else
                    {
                        break;
                    }
                }
                var response = BuildEmailCertResponse(email, certificateProfile, encryptionCertificate, signingCertificate, true);  //isPut=true
                response.CacheInvalidated= cahceInvalidationSuccessful;
                return Created<EmailCertResponse>(response.Href, response); 

                
            }
            catch (Exception e)
            {
                string message = "Email Cert Update Failure --> Exception thrown: " + email;
                _log.Error(message, e);

                return InternalServerError(new ApplicationException(message, e));
            }
            finally
            {
                if (encryptionKeyPairToUpdate != null)
                    encryptionKeyPairToUpdate.Reset();
                if (signingKeyPairToUpdate != null)
                    signingKeyPairToUpdate.Reset();
                if (encryptionCertificate != null)
                    encryptionCertificate.Reset();
                if (signingCertificate != null)
                    signingCertificate.Reset();
            }
        }

        private CertificateProfile GetCertificateProfile(EmailUpdateCertRequest model)
        {
            string certProfileName = String.IsNullOrEmpty(model.CertProfileName) ? Certificate.ProfileName : model.CertProfileName;
            if (null == certProfileName)
            {
                string msg = "Certificate ProfileName is NULL";
                throw new ApplicationException(msg);
            }

            _log.Info(certProfileName);
            CertificateProfile cp = FetchCertificateProfileFromDb(certProfileName);

           if (null == cp)
            {
                string msg = String.Format("CertificateProfile.ProfileName=='{0}' not found in DB: {1}", certProfileName, DatabaseName);
                throw new ApplicationException(msg);
            }
            else
            {
                _log.Debug(String.Format("> CertificateProfile '{0}' with Serial Number '{1}' found in DB: ", certProfileName, cp.SigningCertSerialNumber));
            }

            return cp;
        }

        private IHttpActionResult ValidateModelForReissue(string email, EmailUpdateCertRequest model)
        {
            if (model.IsReissue && null == model.CertProfileName) return ValidationFailureBadRequest("CertProfileName is required for Reissue.");
            if (AccountType.NULL == model.AccountType) return ValidationFailureBadRequest("AccountType is required.");
            if (null != model.NameFirst || null != model.NameLast)
            {
                if (!(null != model.NameFirst && null != model.NameLast))
                {
                    return ValidationFailureBadRequest("If used, NameFirst and NameLast are required together.");
                }
            }
            if((null == model.OrganizationName) && (model.AccountType == AccountType.Professional || model.AccountType == AccountType.Organization))
            {
                return ValidationFailureBadRequest("OrganizationName is required when AccountType == Professional || Organization");
            }

            return null;
        }

        private IHttpActionResult ValidationFailureBadRequest(string msg)
        {
            _log.Warn(_route + " >> " + msg);

            return BadRequest(msg);
        }

        private X509Certificate2 UpdateCertKeySpec(string email, X509Certificate2 certToUpdate, KeyPairType keyPairType)
        {
            _log.Debug("> Updating Keyspec for email certificate: " + Certificate.EmailAS1);

            string pin = RetrievePin(email);
            X509Certificate2 updatedCert = ccm.UpdateCertKeySpec(email, certToUpdate, pin);
            ValidateCertSerialNumber(certToUpdate, updatedCert);
            _log.Info(_route + " --> Created updated KeySpec with Serial Number: " + updatedCert.SerialNumber + " --> " + keyPairType.ToString());

            UpdateEmailCertInDbOnUpdateKeyspec(email, updatedCert, keyPairType);
            _log.Info(_route + " --> Updated in DB: " + DatabaseName);

            return updatedCert;
        }

        private X509Certificate2 RenewCert(string email, CertificateProfile certificateProfile, X509Certificate2 certToRenew, DateTime expirationDate, KeyPairType keyPairType)
        {
            _log.Debug("> Renewing email certificate: " + Certificate.EmailAS1);

            string crlUrl = GetCrlUrl(certificateProfile, certToRenew);
            string aiaPath = GetAiaPath(certificateProfile, certToRenew);

            // retrieve signingCert
            X509Certificate2 signingCert = RetrieveSigningCert(certificateProfile.SigningCertSerialNumber);

            X509Certificate2 renewedCert = ccm.RenewCert(certToRenew, signingCert, expirationDate, crlUrl, aiaPath);
            ValidateCertSerialNumber(certToRenew, renewedCert);
            _log.Info(_route + " --> Created renew key pair with Serial Number: " + renewedCert.SerialNumber + " --> " + keyPairType.ToString());

            UpdateEmailCertInDbOnRenew(email, renewedCert, keyPairType);
            _log.Info(_route + " --> Updated in DB: " + DatabaseName);

            return renewedCert;
        }

        private void ValidateCertSerialNumber(X509Certificate2 x509CertToUpdate, X509Certificate2 certificate)
        {
            if (x509CertToUpdate.SerialNumber.CompareTo(certificate.SerialNumber) != 0)
            {
                SerialNumberMismatch(x509CertToUpdate, certificate);
            }
        }

        private void ReissueCert(string email, EmailUpdateCertRequest model, CertificateProfile cp, DateTime expirationDate, ref X509Certificate2 encryptionX509, ref X509Certificate2 signingX509)
        {
            ValidateCrlRevokeTimespan(Certificate);
            _log.Debug("> Reissuing email certificate: " + Certificate.EmailAS1);

            X509Certificate2 signingCert = GetSigningCert(email, cp.SigningCertSerialNumber);
            _log.Debug("> SigningCert Serial Number: " + cp.SigningCertSerialNumber);

            string ekuOidString = cp.EnhancedKeyUsageOID;
            string[] ekuOid = ekuOidString.Split(';');

            X509Certificate2 newEncryptionX509 = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION, 
                DnBuilder.BuildForReissue(email, model, encryptionX509),
                signingCert,
                expirationDate,
                cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
            );
            _log.Info(_route + " --> Created reissue key pair with Serial Number: " + newEncryptionX509.SerialNumber + " --> " + KeyPairType.Encryption.ToString());

            X509Certificate2 newSigningX509 = ccm.CreateCert(CertificateType.CLIENT_SIGNING,
                DnBuilder.BuildForReissue(email, model, signingX509),
                signingCert,
                expirationDate,
                cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
            );
            _log.Info(_route + " --> Created reissue key pair with Serial Number: " + newSigningX509.SerialNumber + " --> " + KeyPairType.Signing.ToString());

            UpdateEmailCertInDbOnReissue(email, cp.ProfileName, newEncryptionX509, newSigningX509);
            _log.Info(_route + " --> Updated in DB: " + DatabaseName);

            //RevokeCertificate(new X509Certificate2(encryptionX509), signingCert.SerialNumber, email);
            //_log.Info(_route + " -->  Key pair queued for revocation with Serial Number: " + encryptionX509.SerialNumber + " --> " + KeyPairType.Encryption.ToString());

            X509Certificate2 oldEncryptionSignerCert = ccm.RetrieveCertFromStore(encryptionX509.Issuer);
            if (oldEncryptionSignerCert != null)
            {
                RevokeCertificate(new X509Certificate2(encryptionX509), oldEncryptionSignerCert.SerialNumber, email);
                _log.Info(_route + " -->  Key pair queued for revocation of encryption cert with Serial Number: " + encryptionX509.SerialNumber + " --> " + KeyPairType.Encryption.ToString());

            }
            else
            {
                _log.Info(_route + " --> Old signing cert not found for encryptoin cert   with Serial Number: " + encryptionX509.SerialNumber + " --> So no revokation executed");
            }
            if (encryptionX509.SerialNumber != signingX509.SerialNumber)
            {
                //RevokeCertificate(new X509Certificate2(signingX509), signingCert.SerialNumber, email);
                //_log.Info(_route + " --> Key pair queued for revocation with Serial Number: " + signingX509.SerialNumber + " --> " + KeyPairType.Signing.ToString());
                X509Certificate2 oldSigningSignerCert = ccm.RetrieveCertFromStore(signingX509.Issuer);
                if (oldSigningSignerCert != null)
                {
                    RevokeCertificate(new X509Certificate2(signingX509), oldSigningSignerCert.SerialNumber, email);
                    _log.Info(_route + " --> Key pair queued for revocation of signing cert with Serial Number: " + signingX509.SerialNumber + " --> " + KeyPairType.Signing.ToString());
                }
                else
                {
                    _log.Info(_route + " --> Old signing cert not found for signing cert   with Serial Number: " + signingX509.SerialNumber + " --> So no revokation executed");
        
                }

            }

            encryptionX509 = newEncryptionX509;
            signingX509 = newSigningX509;
        }

        private X509Certificate2 GetSigningCert(string email, string sn)
        {
            X509Certificate2 signingCert = RetrieveSigningCert(sn);
            if (null == signingCert)
            {
                SigningCertNotFound(email, sn);
            }
            return signingCert;
        }

        private IHttpActionResult ValidateCrlRevokeTimespan(Certificate certificate)
        {
            if (null != certificate.DateModified)
            {
                int minutes = Config.CrlRevokeTimespanInMinutes;
                _log.Debug(String.Format("> DateModified: {0}", certificate.DateModified));
                _log.Debug(String.Format("> DateModified + {0} Minute{2}: {1}", minutes, certificate.DateModified.Value.AddMinutes(minutes), (minutes != 1 ? "s" : String.Empty)));
                _log.Debug(String.Format("> DateTime.Now: {0}", DateTime.Now));

                var tsim = Config.CrlRevokeTimespanInMinutes;
                var x = certificate.DateModified.Value.AddMinutes(Config.CrlRevokeTimespanInMinutes);
                var dm = certificate.DateModified;

                if (null != certificate.DateModified && certificate.DateModified.Value.AddMinutes(Config.CrlRevokeTimespanInMinutes) > DateTime.Now)
                {
                    string msg = String.Format("Certificate is new or has been queued for CRL Revoke. Retry request in {0} minutes.", Config.CrlRevokeTimespanInMinutes);
                    _log.Warn(_route + " >> " + msg);

                    return BadRequest(msg);
                }
            }
            return null;
        }

        private IHttpActionResult BadModel(string email)
        {
            _log.Info(_route + "--> Bad Model: " + ModelState.ToString()); 

            return BadRequest(ModelState);
        }

        private static string GetCrlUrl(CertificateProfile certificateProfile, X509Certificate2 certToUpdate)
        {
            if (null != certificateProfile) return certificateProfile.CRLURL;

            return Utils.InterrogateCertForCrlDistributionPoint(certToUpdate);
        }

        private static string GetAiaPath(CertificateProfile certificateProfile, X509Certificate2 certToUpdate)
        {
            if (null != certificateProfile) return certificateProfile.AIAPath;

            return Utils.InterrogateCertForAiaPath(certToUpdate);
        }

        private void SerialNumberMismatch(X509Certificate2 certToUpdate, X509Certificate2 updatedCert)
        {
            string message = string.Format("Email Cert Renew Failure --> Serial number mismatch: {0} != {1}", certToUpdate.SerialNumber, updatedCert.SerialNumber);

            throw new ApplicationException(message);
        }

        private void ParseRoute(string email, UpdateCertRequestBase model)
        {
            string route = Request.GetRouteData().Route.RouteTemplate;
            _key = email;
            if (route.Contains("renew"))
                model.IsReissue = false;
            else if (route.Contains("reissue"))
                model.IsReissue = true;
            else if (route.Contains("keyspec"))
                model.IsUpdateKeyspec = true;

            _route = "PUT api/v2/certs/email/" + email + "/" + (model.IsReissue ? "reissue" : model.IsUpdateKeyspec ? "keyspec" : "renew");
           
            _log.Info(_route);
            _log.Info(_key);
        }

        private void UpdateEmailCertInDbOnReissue(string email, string certProfileName, X509Certificate2 encryptionX509, X509Certificate2 signingX509)
        {
            try
            {
                Certificate dbRecord = FetchCertificateFromDb(email);

                // save old values
                string oldPin = RetrievePin(email);
                dbRecord.LastPrivateKeyEncryption = dbRecord.PrivateKeyEncryption;
                dbRecord.LastEcryptionPIN = oldPin;
                dbRecord.LastCertReplaceDate = DateTime.Now;
                dbRecord.ProfileName = certProfileName;
                db.SaveChanges();

                string pin = GeneratePin();
                dbRecord.PIN = pin;

                // encryption
                byte[] pfxEncryption = encryptionX509.Export(X509ContentType.Pfx, pin);
                dbRecord.PrivateKeyEncryption = pfxEncryption;
                byte[] publicKey = encryptionX509.Export(X509ContentType.Cert);
                dbRecord.PublicKeyEncryption = publicKey;
                dbRecord.EncryptionCertExpDate = encryptionX509.NotAfter;

                // signing
                byte[] pfxSigning = signingX509.Export(X509ContentType.Pfx, pin);
                dbRecord.PrivateKeySigning = pfxSigning;
                dbRecord.SigningCertExpDate = signingX509.NotAfter;

                dbRecord.DateModified = DateTime.Now;
                dbRecord.ModifiedBy = "CA Service - Reissue";
                db.SaveChanges();
            }
            catch (Exception e)
            {
                _log.Error(email, e);

                throw e;
            }
        }

        private void UpdateEmailCertInDbOnRenew(string email, X509Certificate2 updatedCert, KeyPairType keyPairType)
        {
            try
            {
                Certificate dbRecord = FetchCertificateFromDb(email);

                var pin = RetrievePin(email);
                dbRecord.PIN = pin;
                byte[] pfx = updatedCert.Export(X509ContentType.Pfx, pin);

                if (KeyPairType.Encryption == keyPairType)
                {
                    dbRecord.PrivateKeyEncryption = pfx;
                    byte[] publicKey = updatedCert.Export(X509ContentType.Cert);
                    dbRecord.PublicKeyEncryption = publicKey;
                    dbRecord.EncryptionCertExpDate = updatedCert.NotAfter;
                }
                else // KeyPairType.Signing
                {
                    dbRecord.PrivateKeySigning = pfx;
                    dbRecord.SigningCertExpDate = updatedCert.NotAfter;
                }

                dbRecord.DateModified = DateTime.Now;
                dbRecord.ModifiedBy = "CA Service - Renew";
                db.SaveChanges();
            }
            catch (Exception e)
            {
                _log.Error(email, e);

                throw e;
            }
        }

        private void UpdateEmailCertInDbOnUpdateKeyspec(string email, X509Certificate2 updatedCert, KeyPairType keyPairType)
        {
            try
            {
                Certificate dbRecord = FetchCertificateFromDb(email);

                var pin = RetrievePin(email);
                dbRecord.PIN = pin;
                byte[] pfx = updatedCert.Export(X509ContentType.Pfx, pin);

                if (KeyPairType.Encryption == keyPairType)
                {
                    dbRecord.PrivateKeyEncryption = pfx;
                    byte[] publicKey = updatedCert.Export(X509ContentType.Cert);
                    dbRecord.PublicKeyEncryption = publicKey;
                }
                else // KeyPairType.Signing
                {
                    dbRecord.PrivateKeySigning = pfx;
                }

                dbRecord.DateModified = DateTime.Now;
                dbRecord.ModifiedBy = "CA Service - UpdateKeyspec";
                db.SaveChanges();
            }
            catch (Exception e)
            {
                _log.Error(email, e);

                throw e;
            }
        }


        [Route("{email}/invalidate")]
        [HttpPut] 
        public  IHttpActionResult InValidateCache(string email)
        {
              try
            {
                  bool cahceInvalidationSuccessful=InvalidateCacheEntries(email); 
                   for (int i = 0; i <2; i++) {
                    if (!cahceInvalidationSuccessful) { 
                         cahceInvalidationSuccessful=InvalidateCacheEntries(email); 
                    }
                    else
                    {
                        break;
                    }
                }
                  
                 return ResponseMessage(Request.CreateResponse(HttpStatusCode.OK,  cahceInvalidationSuccessful.ToString()));
                  
            }
            catch (Exception e)
            {
                string message = "Email Cert cache invalidation  Failure --> Exception thrown: " + email;
                _log.Error(message, e); 
                return InternalServerError(new ApplicationException(message, e));
            } 
             
             
        }

        [Route("flushCache")]
        [HttpPut] 
        public  IHttpActionResult FlushCache( )
        {
              try
            {
                  bool cachFlushSuccessfull=FlushAllCache(); 
                   for (int i = 0; i <2; i++) {
                    if (!cachFlushSuccessfull) { 
                         cachFlushSuccessfull=FlushAllCache(); 
                    }
                    else
                    {
                        break;
                    }
                   }

                  return ResponseMessage(Request.CreateResponse(HttpStatusCode.OK,  cachFlushSuccessfull.ToString()));
                 
                  
            }
            catch (Exception e)
            {
                string message = "Email Cert cache invalidation  Failure --> Exception thrown: " ;
                _log.Error(message, e); 
                return InternalServerError(new ApplicationException(message, e));
            } 
             
             
        }
		
    }
}