using CERTENROLLLib;
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
using Newtonsoft.Json;
using Ses.CaService.Core.Crypto;
using System.Text;
using System.IO;

namespace Ses.CaService.Controllers
{
    public partial class TlsCertsController : BaseController
    {
        /// <summary>
        /// Create new X509 certificate
        /// </summary>
        [Route("")]
        [HttpPost]
        [ResponseType(typeof(TlsCertResponse))]
        public IHttpActionResult Create(TlsCreateCertRequest model)
        {
            _route = "POST api/v2/certs/tls";
            _log.Info(_route);

            if (!ModelState.IsValid) return BadRequest(ModelState);

            string data = JsonConvert.SerializeObject(model);
            _log.Debug("> ModelState.IsValid --> " + data); 

            //StringBuilder str= new StringBuilder(); 
            //string[] lines=null;
            //if( model.CSRARRAY==null){
            //  lines = System.IO.File.ReadAllLines(@"C:\Users\Public\CertRequest.txt");
            //   foreach (string line in lines)
            //    {
                     
            //        str.AppendLine(line);
            //    }
            //}else{ 
            //      lines=model.CSRARRAY; 
            //        foreach (string line in lines)
            //        {
                        
            //            str.AppendLine(line);
                        
            //        }
              
            // }
            //  model.CSR=str.ToString(); 
             Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest  req = null;
             if  (model.CSRBYTEARRAY!=null){ 
               string  base64Decoded = System.Text.ASCIIEncoding.ASCII.GetString(model.CSRBYTEARRAY);
               using(TextReader sr = new StringReader(base64Decoded ))  
                {  
                    Org.BouncyCastle.OpenSsl.PemReader pemParser = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                    try{           
                        
                        Object parsedObj = pemParser.ReadObject();
                        if (parsedObj.GetType()== typeof(Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest)) {
                                 req = ( Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest ) parsedObj;
                          }
                     }
                     catch ( Exception e) {
                      
                         _log.Error("Error parsing the csr: " +base64Decoded,e);
                          return   InValidCSR();
        
                      }
               }
                string subjectName=   req.GetCertificationRequestInfo().Subject.ToString();
                string cn = DnFields.getValByAttributeTypeFromIssuerDN(subjectName, "cn");
                string o= DnFields.getValByAttributeTypeFromIssuerDN(subjectName, "o");
                string ou = DnFields.getValByAttributeTypeFromIssuerDN(subjectName, "ou");

                if (!(String.Equals(model.OrgId.ToString(), o)))
                {     
                     
                     string message = string.Format("OrgId in the CSR {0} is different then the orgId passed  in the model {1}", o, model.OrgId.ToString());
                     _log.Debug(message);
                    return InValidOrgId(o ,model.OrgId.ToString()); 
                }
                    
                if (!(String.Equals(model.VendorId.ToString(), ou)))
                {
                     string message = string.Format("OrgId in the CSR {0} is different then the orgId passed  in the model {1}", ou, model.VendorId.ToString());
                     _log.Debug(message);
                     return InValidVendorId(ou,model.VendorId.ToString());

                }
             } 
            try
            {
                if (CertificateInDb(model.OrgId)) { 
                   if (model.CSRBYTEARRAY != null)
                   {
                    
                       IHttpActionResult deleteResponse=this.Delete(model.OrgId); 
                       if (deleteResponse.GetType()!=typeof(System.Web.Http.Results.OkNegotiatedContentResult<string>)){  
                            return InternalServerError(new ApplicationException("There was an error in deleting the existing CSR certificate"));
                       }
                        
                   }
                   else { 
                     return CertAlreadyExists(model.OrgId);
                   }
                }
                

                CX500DistinguishedName dn;
                string certProfileName = model.CertProfileName;
                dn = DnBuilder.CreateTlsDn(new DnFields()
                    {
                        CN = model.OrganizationName,
                        O = model.OrgId,
                        OU = model.VendorId,
                        L = model.City,
                        S = model.State,
                        C = model.Country
                    });
                _log.Info(_route + " --> Subject: " + dn.Name);
                
                CertificateProfile cp = FetchCertificateProfileFromDb(certProfileName);
                if (null == cp) return CertProfileNotFound(model.OrgId, certProfileName);
                _log.Debug("> Found CertProfileName: " + certProfileName);

                string sn = cp.SigningCertSerialNumber;
                X509Certificate2 signingCert = new X509Certificate2();            
                signingCert = RetrieveSigningCert(sn);
                if (null == signingCert) return SigningCertNotFound(model.OrgId, sn);
                _log.Debug("> SigningCert Serial Number: " + cp.SigningCertSerialNumber);
                
                DateTime expireOn = DateTime.Now.AddMonths(model.TimeToLiveInMonths);
                string ekuOidString = cp.EnhancedKeyUsageOID;
                string[] ekuOid = ekuOidString.Split(';');

                  X509Certificate2 newTlsCert=null;
                 if (model.CSRBYTEARRAY != null)
                {

                   newTlsCert = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION_SIGNING,
                   req, signingCert, expireOn, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid);
                  _log.Info(_route + " --> Created certificate with Serial Number: " + newTlsCert.GetSerialNumberString());
                    InsertCertsWithRequestIntoDb(newTlsCert, model.OrgId, model.VendorId, model.OrganizationName, certProfileName);
                    _log.Info(_route + " --> Inserted into DB: " + DatabaseName);
                }
                else
                {

                    newTlsCert = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION_SIGNING,dn, signingCert, expireOn, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid); 
                    _log.Info(_route + " --> Created certificate with Serial Number: " + newTlsCert.GetSerialNumberString());
                    InsertIntoDb(newTlsCert, model.OrgId, model.VendorId, model.OrganizationName, certProfileName);
                    _log.Info(_route + " --> Inserted into DB: " + DatabaseName);
                }


                //X509Certificate2 newTlsCert = ccm.CreateCert(CertificateType.CLIENT_ENCRYPTION_SIGNING, 
                //    dn, signingCert, expireOn, cp.CRLURL, cp.AIAPath, cp.CertPolicyOID, cp.LOAPolicyOID, cp.CategoryOID, ekuOid
                //);
                //_log.Info(_route + " --> Created certificate with Serial Number: " + newTlsCert.GetSerialNumberString());
                
                //InsertIntoDb(newTlsCert, model.OrgId, model.VendorId, model.OrganizationName, certProfileName);
                //_log.Info(_route + " --> Inserted into DB: " + DatabaseName);
                
                var response = BuildTlsCertResponse(model.OrgId, cp, newTlsCert);

                return Created<TlsCertResponse>(response.Href, response); 
            }
            catch (Exception e)
            {
                string message = "TLS Cert Create Failure --> Exception thrown: " + model.OrgId;
                _log.Error(message, e);

                return InternalServerError(e);
            }
        }
		

        private static IHttpActionResult SigningCertNotFound(string orgId, string sn)
        {
            string message = string.Format("TLS Cert Failure --> SigningCert not found: {0} --> SigningCertSerialNumber: {1}", orgId, sn);
            throw new ApplicationException(message);
        }

        private IHttpActionResult CertProfileNotFound(string orgId, string certProfileName)
        {
            string message = string.Format("TLS Cert Failure --> CertProfile not found: {0} --> CertProfileName: {1}", orgId, certProfileName);
            throw new ApplicationException(message);
        }

        private IHttpActionResult CertAlreadyExists(string orgId)
        {
            string message = _route + " >> TLS Cert Create Failure --> Certificate already exists for: " + orgId;
            _log.Warn(message);

            return BadRequest(message);
        }


        	private static IHttpActionResult InValidCSR( )
        {
            string message = string.Format("Invalid CSR");
            throw new ApplicationException(message);
        }

        private static IHttpActionResult InValidOrgId(string csrOrgId,string modelOrgId )
        {
             string message = string.Format("Invalid CSR.Value of O (OrgId) in the CSR {0} is different then the one registered in the system {1}", csrOrgId, modelOrgId);
          
             throw new ApplicationException(message);
        }

        private static IHttpActionResult InValidVendorId(string csrVendorId,string modelVendorId )
        {
             string message = string.Format("Invalid CSR.Value of OU (VendorId) in the CSR {0} is different then the one registered in the system {1}", csrVendorId, modelVendorId);
          
            throw new ApplicationException(message);
        }




        private void InsertIntoDb(X509Certificate2 tlsCert, string orgId, string vendorId, string organizationName, string certProfileName)
        {
            string pin = GeneratePin();
            byte[] pfx = tlsCert.Export(X509ContentType.Pfx, pin);

            db.TlsCertificates.Add(new TlsCertificate()
            {                
                OrgId = orgId,
                VendorId = vendorId,
                OrganizationName = organizationName,
                CreatedBy = "CA Service",
                DateCreated = DateTime.Now,
                PrivateKeyEncryption = pfx,
                PrivateKeySigning = pfx,
                ProfileName = certProfileName,
                PIN = pin,
            });
            db.SaveChanges();
        }

         private void InsertCertsWithRequestIntoDb(X509Certificate2 tlsCert, string orgId, string vendorId, string organizationName, string certProfileName)
        {
            
            byte[] cert = tlsCert.Export(X509ContentType.Cert);

            db.TlsCertificates.Add(new TlsCertificate()
            {
                OrgId = orgId,
                VendorId = vendorId,
                OrganizationName = organizationName,
                CreatedBy = "CA Service",
                DateCreated = DateTime.Now,
                PrivateKeyEncryption = cert,
                PrivateKeySigning = cert,
                ProfileName = certProfileName ,
                PIN="PUBLIC-KEY-ONLY"
            });
            db.SaveChanges();
        }
    }
}