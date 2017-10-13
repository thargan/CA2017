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
using Ses.CaService.Crypto;
using Ses.CaService.Core;
using Newtonsoft.Json;
using Ses.CaService.Core.Crypto;
using System.Net.Http;
using Limilabs.Mail;

namespace Ses.CaService.Controllers
{
    public partial class EmailCertsController : BaseController
    {
        private DnBuilder _dnBuilder;

        /// <summary>
        /// Create new X509 certificate
        /// </summary>
        [Route("")]
        [HttpPost]
        [CheckNameFirstAndNameLast()]
        public IHttpActionResult Create(EmailCreateCertRequest model)
        {
            string route = Request.GetRouteData().Route.RouteTemplate;

            _route = "POST api/v2/certs/email";
            _log.Info(_route);

            if (!ModelState.IsValid) return BadRequest(ModelState);

            string data = JsonConvert.SerializeObject(model);
            _log.Debug("> ModelState.IsValid --> " + data);

            try
            {
                if (CertificateInDb(model.Email)) return CertAlreadyExists(model.Email);

                string cn = null;

                switch (model.AccountType)
                {
                    case AccountType.Patient:
                        var resultPatient = ValidateModelForPatient(model);
                        if (null != resultPatient) return resultPatient;

                        cn = Utils.BuildCommonName(model.NameFirst, model.NameLast);
                        break;

                    case AccountType.Professional:
                        var resultProfessional = ValidateModelForProfessional(model);
                        if (null != resultProfessional) return resultProfessional;

                        cn = Utils.BuildCommonName(model.NameFirst, model.NameLast, model.NameTitle);
                        break;

                    case AccountType.Organization:
                        ValidateModelForOrganization(model);
                        break;
                };

                _dnBuilder = new DnBuilder();
                _dnBuilder.DN = DnBuilder.Build(model, cn);

                _log.Info(_route + " --> Subject: " + _dnBuilder.DN.Name);

                string certProfileName = model.CertProfileName;
                CertificateProfile cp = FetchCertificateProfileFromDb(certProfileName);
                if (null == cp) CertProfileNotFound(model.Email, certProfileName);

                _log.Debug("> Found Certificate Profile: " + certProfileName);

                string sn = cp.SigningCertSerialNumber;
                X509Certificate2 signingCert = new X509Certificate2();            
                signingCert = RetrieveSigningCert(sn);
                if (null == signingCert) SigningCertNotFound(model.Email, sn);

                _log.Debug("> SigningCert Serial Number: " + cp.SigningCertSerialNumber);
                
                DateTime expirationDate = DateTime.Now.AddMonths(model.TimeToLiveInMonths);
                string ekuOidString = cp.EnhancedKeyUsageOID;
                string[] ekuOid = ekuOidString.Split(';');
                X509Certificate2 newEmailEncryptionCert = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION, 
                    _dnBuilder.DN, signingCert, expirationDate, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
                );
                _log.Info(_route + " --> Created email encryption certificate with Serial Number: " + newEmailEncryptionCert.GetSerialNumberString());

                X509Certificate2 newEmailSigningCert = ccm.CreateCert(CertificateType.CLIENT_SIGNING, 
                    _dnBuilder.DN, signingCert, expirationDate, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
                );
                _log.Info(_route + " --> Created email signing certificate with Serial Number: " + newEmailEncryptionCert.GetSerialNumberString());

                InsertIntoDb(newEmailEncryptionCert, newEmailSigningCert, model.Email, certProfileName, model.CreatedBy);
                _log.Info(_route + " --> Inserted into DB: " + DatabaseName);

                var response = BuildEmailCertResponse(model.Email, cp, newEmailEncryptionCert, newEmailSigningCert);
                
                return Created<EmailCertResponse>(response.Href, response); 
            }
            catch (Exception e)
            {
                string message = "Email Cert Create Failure --> Exception thrown: ";
                _log.Error(message, e);

                return InternalServerError(e);
            }
        }


        /// <summary>
        /// Retrieve PFX with encryption key pair
        /// </summary>
        /// <param name="email">Email Address</param>
        [Route("{email}/decrypt")]
        [HttpPost]
        [ResponseType(typeof(byte[]))]
        public IHttpActionResult GetDecryptedFile(string email, byte[] fileToDecrypt)
        {
            _route = String.Format("GET {0}/{1}/key", _baseUri, email);
            _log.Info(_route);

            try
            {
                byte[] key = null;

                if (!CertificateInDb(email)) return CertNotFound(email, "Key");

                key = RetrievePfxWithBlankPassword(email, KeyPairType.Encryption);
                if (key == null) return CertNotFound(email, "Key");


                MailBuilder mailBldr = new MailBuilder();
                mailBldr.SMIMEConfiguration.DecryptAutomatically = false;
                mailBldr.SMIMEConfiguration.ExtractSignedAutomatically = false;

                IMail mail = mailBldr.CreateFromEml(fileToDecrypt);

                var cert = new X509Certificate2(key, "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                _log.InfoFormat("Starting Decryption Operations");
                // Decrypting Message
                IMail decriptedMail = mail.Decrypt(cert);
                _log.InfoFormat(". . . completed Decrypt operation");
                byte[] SignedMsgBytes = decriptedMail.Render();

                return Ok(SignedMsgBytes);
                //return new OctetStreamResult(SignedMsgBytes);
            }
            catch (Exception e)
            {
                return HandleException(email, e);
            }
        }
        private IHttpActionResult ValidateModelForPatient(EmailCreateCertRequest model)
        {
            if (null == model.NameFirst) return ValidationFailureBadRequest("NameFirst is required.");
            if (null == model.NameLast) return ValidationFailureBadRequest("NameLast is required.");

            return null;
        }

        private IHttpActionResult ValidateModelForProfessional(EmailCreateCertRequest model)
        {
            if (null == model.NameFirst) return ValidationFailureBadRequest("NameFirst is required.");
            if (null == model.NameLast) return ValidationFailureBadRequest("NameLast is required.");
            if ((null == model.OrganizationName) && (model.AccountType == AccountType.Professional))
            {
                return ValidationFailureBadRequest("OrganizationName is required when AccountType == Professional");
            }

            return null;
        }

        private IHttpActionResult ValidateModelForOrganization(EmailCreateCertRequest model)
        {
            if ((null == model.OrganizationName) && (model.AccountType == AccountType.Organization))
            {
                return ValidationFailureBadRequest("OrganizationName is required when AccountType == Organization");
            }

            return null;
        }

        private static void SigningCertNotFound(string email, string sn)
        {
            string message = string.Format("Email Cert Failure --> SigningCert not found: {0} --> SigningCertSerialNumber: {1}", email, sn);
            throw new ApplicationException(message);
        }

        private void CertProfileNotFound(string email, string certProfileName)
        {
            string message = string.Format("Email Cert Failure --> CertProfile not found: {0} --> CertProfileName: {1}", email, certProfileName);
            throw new ApplicationException(message);
        }

        private IHttpActionResult CertAlreadyExists(string email)
        {
            string message = _route + " >> Email Cert Create Failure --> Certificate already exists for: " + email;
            _log.Warn(message);
            return Conflict();
        }
        
        private void InsertIntoDb(X509Certificate2 emailEncryptionCert, X509Certificate2 emailSigningCert, string email, string certProfileName, string createdBy)
        {
            _log.Debug("> Inserting into DB: " + email);

            string pin = GeneratePin();

            // Encryption Cert
            byte[] publicKeyEncryption = emailEncryptionCert.Export(X509ContentType.Cert);
            byte[] pfxPrivateKeyEncryption = emailEncryptionCert.Export(X509ContentType.Pfx, pin);
            
            // Signing Cert
            // NO PUBLIC KEY!
            byte[] pfxPrivateKeySigning = emailSigningCert.Export(X509ContentType.Pfx, pin);

            db.Certificates.Add(new Certificate()
            {
                EmailAS1 = email,
                CreatedBy = (String.IsNullOrWhiteSpace(createdBy) ? "CA Service" : createdBy),
                DateCreated = DateTime.Now,
                ProfileName = certProfileName,
                PIN = pin,

                // Encryption Cert
                PublicKeyEncryption = publicKeyEncryption,
                PrivateKeyEncryption = pfxPrivateKeyEncryption,
                EncryptionCertExpDate = emailEncryptionCert.NotAfter,

                // Signing Cert
                // NO PUBLIC KEY!
                PrivateKeySigning = pfxPrivateKeySigning,
                SigningCertExpDate = emailSigningCert.NotAfter
            });
            db.SaveChanges();
        }
    }
}