using CERTENROLLLib;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using System.IO;
using System.Text.RegularExpressions;
using Ses.CaService.Core.Crypto;
using System.Collections;

namespace Ses.CaService.Crypto
{
    public class ClientCertManager : BaseCertManager
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(ClientCertManager));

        public X509Certificate2 CreateCert(CertificateType certType,
            CX500DistinguishedName dn, X509Certificate2 signerCert, DateTime expirationDate,
            string crlUrl, string aiaPath, string certPolicy, string loaPolicy, string categoryOid, params string[] ekuOid)
        {
            string certPolicyOid = certPolicy;
            string loaPolicyOid = loaPolicy;

            CX509PrivateKey privateKey = CreatePrivateKey(KeyLength);
            CObjectId hashAlgorithm = Hashing.InitializeSecureHashAlgorithm("SHA256");

            CX509CertificateRequestCertificate clientCert = CreateSignedCert(privateKey, dn, signerCert, expirationDate, hashAlgorithm);
            AddSubjectAltName(dn, clientCert);

            AuthorityInformationAccess aia = CreateAuthorityInformationAccess(OidType.AIA_DOI, aiaPath);
            CX509Extension aiaOid = CreateAiaOid(OidType.AIA_OID, aia);
            clientCert.X509Extensions.Add(aiaOid);

            CX509ExtensionEnhancedKeyUsage eku = CreateEku(false, ekuOid);
            clientCert.X509Extensions.Add((CX509Extension)eku);

            CX509ExtensionKeyUsage keyUsage = CreateExtensionKeyUsage(certType);
            clientCert.X509Extensions.Add((CX509Extension)keyUsage);

            CX509ExtensionBasicConstraints basicConstraints = CreateBasicConstraints(false, true);
            clientCert.X509Extensions.Add((CX509Extension)basicConstraints);

            CX509Extension crl = CreateCrlDistributionPoint(crlUrl);
            clientCert.X509Extensions.Add(crl);

            // Critical Certificate policies
            CCertificatePolicy clientCertPolicy = CreateCriticalCertPolicy(certPolicyOid);
            CCertificatePolicy loaCertPolicy = CreateCriticalCertPolicy(loaPolicyOid);
            CCertificatePolicy category = CreateCriticalCertPolicy(categoryOid);
            CX509ExtensionCertificatePolicies criticalCertPolicies = CreateCertPolicies(clientCertPolicy, loaCertPolicy, category);
            clientCert.X509Extensions.Add((CX509Extension)criticalCertPolicies);

            // Encode the publicKey
            string base64EncodedCertificate = CreateBase64EncodedPkcs12(clientCert);
            X509Certificate2 clientCertificate = new X509Certificate2(Convert.FromBase64String(base64EncodedCertificate), Password, X509KeyStorageFlags.Exportable);
            RemoveCertFromStore(clientCertificate.Subject);

            return clientCertificate;
        }


      //Overload to accept the csr request
        public X509Certificate2 CreateCert(CertificateType certType,Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest req ,
                                           X509Certificate2 signerCert, DateTime expirationDate,
                                           string crlUrl, string aiaPath, string certPolicy, string loaPolicy, string categoryOid, params string[] ekuOid)
        {
            

                    string certPolicyOid = certPolicy;
                    string loaPolicyOid = loaPolicy;  
                    DateTime time5MinutesBefore = DateTime.Now.Subtract (new TimeSpan(0,5, 0));  
                    DateTime startDate = DateTime.Now;
                   // DateTime expiryDate = startDate.AddYears(100);
                    Org.BouncyCastle.Math.BigInteger serialNumber = new Org.BouncyCastle.Math.BigInteger(32, new Random()); 
                     
                    string signerCN =signerCert.SubjectName.Name.ToString();
                   // string issueName=signerCert.IssuerName.Name.ToString();
                    string cn = DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "cn");
                    string o= DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "o");
                    string ou = DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "ou");
                    string l = DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "l");
                    string c = DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "c");
                    string s = DnFields.getValByAttributeTypeFromIssuerDN(signerCN, "s");
                    if (cn == null)
                    {
                        _log.InfoFormat(" Crl file {0} issuer cert's DN {1}  has no CN",  signerCN);
                 
                    } 
                    string issuerName = DnBuilder.CreateBountyCastleTLSDnString(new DnFields()
                    {
                        CN = cn,
                        O =o,
                        OU =ou,
                        L =l,
                        S =s,
                        C = c
                    });
                    Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo  reqInfo= req.GetCertificationRequestInfo(); 
                    Org.BouncyCastle.Asn1.X509.X509Name issuerDName = new  Org.BouncyCastle.Asn1.X509.X509Name( issuerName);  
                    Org.BouncyCastle.Asn1.X509.X509Name cName =  reqInfo.Subject ;
                    Org.BouncyCastle.X509.X509V3CertificateGenerator certGen = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
                    certGen.SetSerialNumber(serialNumber);
                    certGen.SetIssuerDN(issuerDName);
                    certGen.SetNotBefore(startDate);
                    certGen.SetNotAfter(expirationDate);
                    certGen.SetSubjectDN(cName);
                    certGen.SetSignatureAlgorithm("SHA256withRSA");
                    certGen.SetPublicKey( req.GetPublicKey()); 
                    //Basic Constraint
                    certGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints,true,new  Org.BouncyCastle.Asn1.X509.BasicConstraints(false ) ); 
                
                    //Authority Information Access
                    Org.BouncyCastle.Asn1.X509.AuthorityInformationAccess aia = CreateAuthorityInformationAccess(OidType.AIA_DOI, aiaPath);                  
                    Org.BouncyCastle.Asn1.X509.AccessDescription caIssuers = new Org.BouncyCastle.Asn1.X509.AccessDescription(Org.BouncyCastle.Asn1.X509.AccessDescription.IdADCAIssuers,
                    new  Org.BouncyCastle.Asn1.X509.GeneralName( Org.BouncyCastle.Asn1.X509.GeneralName.UniformResourceIdentifier, new Org.BouncyCastle.Asn1.DerIA5String(aiaPath)));
                    Org.BouncyCastle.Asn1.Asn1EncodableVector aia_ASN = new Org.BouncyCastle.Asn1.Asn1EncodableVector();
                    aia_ASN.Add(caIssuers);  
                    certGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityInfoAccess, false, new Org.BouncyCastle.Asn1.DerSequence(aia_ASN));

            
                    //Certificate Policies
                    Org.BouncyCastle.Asn1.X509.PolicyInformation[] certPolicies = new Org.BouncyCastle.Asn1.X509.PolicyInformation[3];
                    certPolicies[0] = new Org.BouncyCastle.Asn1.X509.PolicyInformation(  new Org.BouncyCastle.Asn1.DerObjectIdentifier(certPolicyOid));
                    certPolicies[1] = new Org.BouncyCastle.Asn1.X509.PolicyInformation(new Org.BouncyCastle.Asn1.DerObjectIdentifier(loaPolicyOid));
                    certPolicies[2]   = new Org.BouncyCastle.Asn1.X509.PolicyInformation(new Org.BouncyCastle.Asn1.DerObjectIdentifier(categoryOid));
    
                    Org.BouncyCastle.Asn1.DerSequence policyExtensions = new  Org.BouncyCastle.Asn1.DerSequence( certPolicies ); 
                    certGen.AddExtension (Org.BouncyCastle.Asn1.X509.X509Extensions.CertificatePolicies, false, policyExtensions);
            
                    //CRL Distribution Points
                    Org.BouncyCastle.Asn1.X509.DistributionPointName distPointOne = new Org.BouncyCastle.Asn1.X509.DistributionPointName(new GeneralNames(
                    new Org.BouncyCastle.Asn1.X509.GeneralName(Org.BouncyCastle.Asn1.X509.GeneralName.UniformResourceIdentifier,crlUrl))); 
                    Org.BouncyCastle.Asn1.X509.DistributionPoint[] distPoints = new Org.BouncyCastle.Asn1.X509.DistributionPoint[1];
                    distPoints[0] = new Org.BouncyCastle.Asn1.X509.DistributionPoint(distPointOne, null, null);  
                    certGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlDistributionPoints, false, new Org.BouncyCastle.Asn1.X509.CrlDistPoint(distPoints));   
                  
                    //Key Usage
                    // CertificateType.CLIENT_ENCRYPTION_SIGNING:
                    certGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.KeyUsage, false, new Org.BouncyCastle.Asn1.X509.KeyUsage(Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));


                    // Extended Key usage: Client authentication
                    ArrayList KeyPurposeIds= new ArrayList(); 
                    foreach (string oid in ekuOid)
                    {
                        KeyPurposeIds.Add( new Org.BouncyCastle.Asn1.DerObjectIdentifier(oid.Trim()));
                    }
                    certGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.ExtendedKeyUsage.Id,false,new  Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage(KeyPurposeIds)); 
                
                
                    //Add the authority Key Identifier
                    Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caPair = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(signerCert.PrivateKey);  
                    var authorityKeyIdentifierExtension =new AuthorityKeyIdentifier( SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caPair.Public), new GeneralNames(new GeneralName(issuerDName)), new Org.BouncyCastle.Math.BigInteger(signerCert.GetSerialNumber()));
                    certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);


                    //Add the subject Key Identifier
                     var subjectKeyIdentifierExtension = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(req.GetPublicKey()));
                     certGen.AddExtension( X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);


                    Org.BouncyCastle.X509.X509Certificate bountyCert = certGen.Generate(caPair.Private);
                    X509Certificate2 clientCert = new X509Certificate2(Org.BouncyCastle.Security.DotNetUtilities.ToX509Certificate(bountyCert));
                    return clientCert;
        }
		
		
        



         
         



        private void AddSubjectAltName(CX500DistinguishedName distinguishedName, CX509CertificateRequestCertificate clientCert)
        {
            string email = ParseEmailFromSubject(distinguishedName.Name);
            if (null != email)
            {
                CX509ExtensionAlternativeNames subjectAltName = CreateAlternativeNamesFromEmail(email);
                clientCert.X509Extensions.Add((CX509Extension)subjectAltName);
            }
        }

        public X509Certificate2 UpdateCertKeySpec(string email, X509Certificate2 certToUpdate, string pin="")
        {
            string pfxFileName = Config.TmpCertFolderPath + email + ".pfx";//@"C:\tmp\certs\"+email+".pfx";
            // write to filesystem
            byte[] certBytes = certToUpdate.Export(X509ContentType.Pfx, pin);
            File.WriteAllBytes(pfxFileName, certBytes);
            // excute certutil importPFX and exportPFX
            Execute(pfxFileName, certToUpdate.SerialNumber, pin);
            // read from filesystem
            X509Certificate2 updatedCert = new X509Certificate2();
            updatedCert.Import(pfxFileName, pin, X509KeyStorageFlags.Exportable);
            RemoveCertFromStore(updatedCert.Subject, new X509Store("My", StoreLocation.CurrentUser)); // TO DO: Use => SerialNumber
            File.Delete(pfxFileName);
            return updatedCert;
        }

        public X509Certificate2 RenewCert(X509Certificate2 x509CertToRenew, X509Certificate2 signingCert, DateTime expirationDate, string crlUrl, string aiaPath)
        {
            CObjectId hashAlgorithm = Hashing.InitializeSecureHashAlgorithm("SHA256");
            X509Store certStore = new X509Store(StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadWrite);
            certStore.Add(x509CertToRenew);

            // inherit private key
            CX509CertificateRequestCertificate newX509Cert = new CX509CertificateRequestCertificate();
            try
            {
                newX509Cert.InitializeFromCertificate(
                    X509CertificateEnrollmentContext.ContextMachine,
                    x509CertToRenew.GetRawCertDataString(),
                    EncodingType.XCN_CRYPT_STRING_HEX,
                    X509RequestInheritOptions.InheritPrivateKey
                );
            }
            catch (Exception ex)
            {
                _log.Error("CX509CertificateRequestCertificate.InitializeFromCertificate Failure --> Serial Number: " + x509CertToRenew.SerialNumber);
                throw ex;
            }

            // Assign values from the original tlsCert
            CX500DistinguishedName dnSubject = new CX500DistinguishedName();
            dnSubject.Encode(x509CertToRenew.SubjectName.Name, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            newX509Cert.Subject = dnSubject;

            CX500DistinguishedName issuerDn = new CX500DistinguishedName();

            issuerDn.Encode(signingCert.Subject, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            //issuerDn.Encode(x509CertToRenew.Issuer, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            newX509Cert.Issuer = issuerDn;
            newX509Cert.NotBefore = DateTime.Now.Subtract(new TimeSpan(24, 0, 0));
            newX509Cert.NotAfter = expirationDate;
            newX509Cert.HashAlgorithm = hashAlgorithm;
            newX509Cert.set_SerialNumber(EncodingType.XCN_CRYPT_STRING_HEX, x509CertToRenew.SerialNumber);

            //AIA
            CreateAia(newX509Cert, issuerDn, aiaPath);

            // CRL
            crlUrl = HandleBadCrl(crlUrl, issuerDn);
            CX509Extension crl = CreateCrlDistributionPoint(crlUrl);
            newX509Cert.X509Extensions.Add(crl);
            _log.Debug("> CRL URL: " + crlUrl);

            ISignerCertificate signerCertificate = new CSignerCertificate();
            signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEX, signingCert.GetRawCertDataString());
            newX509Cert.SignerCertificate = (CSignerCertificate)signerCertificate;
            _log.Debug("> Signer Certificate: " + signingCert.Subject);

            string base64EncodedCertificate = CreateBase64EncodedPkcs12(newX509Cert);
            X509Certificate2 renewedCert = new X509Certificate2(Convert.FromBase64String(base64EncodedCertificate), Password, X509KeyStorageFlags.Exportable);
            RemoveCertFromStore(renewedCert.Subject); // TO DO: Use => SerialNumber

            return renewedCert;
        }

        private static string HandleBadCrl(string crlUrl, CX500DistinguishedName issuerDn)
        {
            // Logic to handle known-bad Crl Distribution Point
            if ("http://directaddress.net/crl" == crlUrl)
            {
                _log.Debug("> Handling bad CRL");

                if (issuerDn.Name.Contains("Direct Provider"))
                {
                    crlUrl = "http://directaddress.net/crl/directaddress.crl";
                }
                else if (issuerDn.Name.Contains("Direct Patient Community"))
                {
                    crlUrl = "http://directaddress.net/crl/patientcommunity.crl";
                }
                else if (issuerDn.Name.Contains("Direct Patient"))
                {
                    crlUrl = "http://directaddress.net/crl/directpatient.crl";
                }
            }
            return crlUrl;
        }


        private static void CreateAia(CX509CertificateRequestCertificate newX509Cert, CX500DistinguishedName issuerDn, string aiaPath = null)
        {
            DerObjectIdentifier aiaOid = new DerObjectIdentifier("1.3.6.1.5.5.7.48.2"); // http://www.oid-info.com/get/1.3.6.1.5.5.7.48.2

            string AIA = aiaPath;
            if (String.IsNullOrWhiteSpace(AIA))
            {
                AIA = "http://www.directaddress.net/public/intermediateCA.cer";

                if (issuerDn.Name.IndexOf("SES Direct Patient Intermediate CA") != -1)
                {
                    AIA = "http://www.directaddress.net/public/PatientIntermediateCA.cer";
                }
                else if (issuerDn.Name.IndexOf("SES Direct Patient Community Intermediate CA") != -1)
                {
                    AIA = "http://www.directaddress.net/public/PatientCommunityIntermediateCA.cer";
                }
            }
            GeneralName generalName = new GeneralName(6, AIA);
            _log.Debug("> AIA: " + AIA);

            AccessDescription ad = new AccessDescription(aiaOid, generalName);
            AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(ad);

            CObjectId oid = new CObjectId();
            oid.InitializeFromValue("1.3.6.1.5.5.7.1.1"); // http://www.oid-info.com/get/1.3.6.1.5.5.7.1.1

            CX509Extension aia = new CX509Extension();
            aia.Initialize(oid, EncodingType.XCN_CRYPT_STRING_BASE64_ANY, Convert.ToBase64String(authorityInfoAccess.GetDerEncoded()));
            newX509Cert.X509Extensions.Add(aia);
        }

        private static CX509ExtensionAlternativeNames CreateAlternativeNamesFromEmail(string email)
        {
            CAlternativeName altName = new CAlternativeName();
            altName.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME, email);
            CAlternativeNames altNames = new CAlternativeNames();
            altNames.Add(altName);
            CX509ExtensionAlternativeNames altNameExt = new CX509ExtensionAlternativeNames();
            altNameExt.InitializeEncode(altNames);

            return altNameExt;
        }

        private static string ParseEmailFromSubject(string dnSubject)
        {
            Regex regex = new Regex("E=(.*)");
            Match match = regex.Match(dnSubject);

            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            return null;
        }

        private static CX509ExtensionEnhancedKeyUsage CreateEku(bool isCritical, params string[] oids)
        {
            CObjectIds ekuOids = new CObjectIds();
            foreach (string oid in oids)
            {
                CObjectId ekuOid = new CObjectId();
                ekuOid.InitializeFromValue(oid.Trim());
                ekuOids.Add(ekuOid);
            }
            CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(ekuOids);
            eku.Critical = isCritical;

            return eku;
        }

        private static void Execute(string pfxFileName, string certSerialNumber, string pin="")
        {
            try
            {
                using (Process myProcess = new Process())
                {
                    ProcessStartInfo startInfo = new ProcessStartInfo();
                    startInfo.UseShellExecute = false;
                    startInfo.FileName = Config.CertUtilExePath; // @"C:\Windows\System32\certutil.exe";
                    startInfo.CreateNoWindow = true;
                    startInfo.RedirectStandardError = true;
                    startInfo.RedirectStandardOutput = true;
                    string pfxImportArgs = string.Format("-p {1} -csp \"Microsoft Enhanced Cryptographic Provider v1.0\" -importPFX -user {0} AT_KEYEXCHANGE", pfxFileName, pin);
                    startInfo.Arguments = pfxImportArgs;

                    myProcess.StartInfo = startInfo;
                    bool ret = myProcess.Start();
                    myProcess.WaitForExit();
                    _log.Debug(string.Format("certutil pfxImportArgs {0}", pfxImportArgs));
                    _log.Debug(string.Format("certutil import pfx exit code {0}", myProcess.ExitCode));
                    _log.Debug(string.Format("certutil import pfx output {0}", myProcess.StandardOutput.ReadToEnd()));
                    _log.Debug(string.Format("certutil import pfx error {0}", myProcess.StandardError.ReadToEnd()));

                    string pfxExportArgs = string.Format("-f -p {2} -exportPFX -user MY {0} {1} NoRoot,NoChain", certSerialNumber, pfxFileName, pin);
                    startInfo.Arguments = pfxExportArgs;

                    ret = myProcess.Start();
                    myProcess.WaitForExit();
                    _log.Debug(string.Format("certutil pfxExportArgs {0}", pfxExportArgs));
                    _log.Debug(string.Format("certutil export pfx exit code {0}", myProcess.ExitCode));
                    _log.Debug(string.Format("certutil export pfx output {0}", myProcess.StandardOutput.ReadToEnd()));
                    _log.Debug(string.Format("certutil export pfx error {0}", myProcess.StandardError.ReadToEnd()));
                }
            }
            catch (Exception e)
            {
                _log.Error(string.Format("Execute cmd certutil importPFX ExportPFX failed for cert {0}, serailNumber {1} with exception {2}",
                    pfxFileName, certSerialNumber, e));
            }
        }
    }
}