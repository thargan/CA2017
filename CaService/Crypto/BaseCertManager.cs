using CERTENCODELib;
using CERTENROLLLib;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Security.Cryptography.X509Certificates;


namespace Ses.CaService.Crypto
{
    public class BaseCertManager
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(BaseCertManager));

        private string _password = String.Empty;
        protected string Password
        {
            get { return _password; }
            set { _password = value; }
        }

        private int _keyLength = 2048;
        protected int KeyLength
        {
            get { return _keyLength; }
            set { _keyLength = value; }
        }

        // Creates a DER encoded PFX
        public string CreateBase64EncodedPkcs12(CX509CertificateRequestCertificate x509Certificate)
        {
            // Part of the encoding process assumes that all times are handled in UTC, so calculate UTC offset and modify expiration date
            int utcHoursOffset = DateTime.UtcNow.Hour - DateTime.Now.Hour;
            if (utcHoursOffset < 0) utcHoursOffset += 24;            
            x509Certificate.NotAfter = x509Certificate.NotAfter.AddHours(utcHoursOffset);
            x509Certificate.NotBefore = x509Certificate.NotBefore.AddHours(utcHoursOffset);
            
            var x509Enrollment = new CX509Enrollment();
            x509Enrollment.InitializeFromRequest(x509Certificate);
            string csr = x509Enrollment.CreateRequest();
            x509Enrollment.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, Password);

            return x509Enrollment.CreatePFX(Password, PFXExportOptions.PFXExportChainWithRoot);
        }

        protected static CX509PrivateKey CreatePrivateKey(int keyLength, X509PrivateKeyExportFlags exportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)
        {
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = keyLength;
            privateKey.ExportPolicy = exportPolicy;
            privateKey.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            privateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_DECRYPT_FLAG | X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
            privateKey.Create();

            return privateKey;
        }

        protected static CX509CertificateRequestCertificate CreateUnsignedCert(CX509PrivateKey privateKey, CX500DistinguishedName subject, DateTime expirationDate, CObjectId hashAlgorithm)
        {
            DateTime time5MinutesBefore = DateTime.Now.Subtract (new TimeSpan(0,5, 0));
            CX509CertificateRequestCertificate cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, string.Empty);
            cert.Subject = subject;
            cert.NotBefore = time5MinutesBefore; 
            cert.NotAfter = expirationDate;
            cert.HashAlgorithm = hashAlgorithm;

            return cert;
        }
        
        protected static CX509CertificateRequestCertificate CreateSignedCert(
            CX509PrivateKey privateKey,
            CX500DistinguishedName subject,
            X509Certificate2 signerCert,
            DateTime expirationDate,
            CObjectId hashAlgorithm)
        {
            CX509CertificateRequestCertificate cert = CreateUnsignedCert(privateKey, subject, expirationDate, hashAlgorithm);
            CSignerCertificate signerCertificate = CreateCSignerCertificate(signerCert);
            cert.SignerCertificate = signerCertificate;

            return cert;
        }

        //Overload to accomodate the client csr
        protected static CX509CertificateRequestCertificate CreateSignedCert(
            string csr,
            X509Certificate2 signerCert,
            DateTime expirationDate,
            CObjectId hashAlgorithm
            )
        {
 
                DateTime time5MinutesBefore = DateTime.Now.Subtract (new TimeSpan(0,5, 0));  
                IX509CertificateRequestPkcs10 pkcs10Req = (IX509CertificateRequestPkcs10)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));
                pkcs10Req.InitializeDecode( csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY);
                pkcs10Req.CheckSignature(Pkcs10AllowedSignatureTypes.AllowedKeySignature);
                CX509CertificateRequestCertificate cert = new CX509CertificateRequestCertificate();
               //CX500DistinguishedName issuerDn = DnBuilder.CreateTlsDn(new DnFields()
               //     {
               //         CN = "SES Root CA",
               //         O ="Secure Exchange Solutions",
               //         OU = "SES Directory Services",
               //         L ="Rockville",
               //         S = "MD",
               //         C = "US"
               //     });
             
                cert.InitializeFromPublicKey(X509CertificateEnrollmentContext.ContextMachine, pkcs10Req.PublicKey, string.Empty);
                cert.Subject=pkcs10Req.Subject;  
               //  cert.Issuer=issuerDn;
                cert.NotBefore = time5MinutesBefore; 
                cert.NotAfter = expirationDate;  
                cert.HashAlgorithm = hashAlgorithm;
                CSignerCertificate signerCertificate = CreateCSignerCertificate(signerCert);
                cert.SignerCertificate = signerCertificate; 
                return cert;
        }
        
        private static CSignerCertificate CreateCSignerCertificate(X509Certificate2 signerCert)
        {
            CSignerCertificate signerCertificate = new CSignerCertificate();
            try
            {
                signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, signerCert.GetRawCertDataString());
            }
            catch (Exception e)
            {
                _log.Error("Signer Certificate Initialization Failure --> Exception Thrown: " + e);
            }
            return signerCertificate;
        }

        protected static CX509ExtensionKeyUsage CreateExtensionKeyUsage(CertificateType certType, bool isCritical = true)
        {
            CX509ExtensionKeyUsage keyUsage = new CX509ExtensionKeyUsage();
            CERTENROLLLib.X509KeyUsageFlags bitwiseEncode = CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE;

            switch(certType)
            {
                case CertificateType.CLIENT_ENCRYPTION_SIGNING:
                    bitwiseEncode =
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DECIPHER_ONLY_KEY_USAGE |
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_AGREEMENT_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE |
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
                    //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NO_KEY_USAGE | 
                    //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
                    //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE;
                    break;

                case CertificateType.CLIENT_ENCRYPTION:
                    bitwiseEncode =
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DECIPHER_ONLY_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_AGREEMENT_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE |
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NO_KEY_USAGE | 
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
                        //CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE;
                    break;

                case CertificateType.CLIENT_SIGNING:
                    bitwiseEncode =
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE;
                    break;

                case CertificateType.ROOT:
                case CertificateType.INTERMEDIATE:
                    bitwiseEncode =
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE |
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                        CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE;
                    break;
            }

            keyUsage.InitializeEncode(bitwiseEncode);
            keyUsage.Critical = isCritical;

            return keyUsage;
        }

        protected static AuthorityInformationAccess CreateAuthorityInformationAccess(OidType derObjectIdentifier, string derUri, int generalNameTag = 6)
        {
            string derOidString = Oid.GetOidString(derObjectIdentifier);
            DerObjectIdentifier doi = new DerObjectIdentifier(derOidString);
            GeneralName location = new GeneralName(generalNameTag, derUri);
            AccessDescription accessDescription = new AccessDescription(doi, location);

            return new AuthorityInformationAccess(accessDescription);
        }

        protected static CX509Extension CreateAiaOid(OidType AIAOidPolicy, AuthorityInformationAccess AIA)
        {
            string aiaOidString = Oid.GetOidString(AIAOidPolicy);
            CObjectId pObjectId = new CObjectId();
            pObjectId.InitializeFromValue(aiaOidString);

            CX509Extension aiaOid = new CX509Extension();
            aiaOid.Initialize(
                pObjectId,
                CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY,
                Convert.ToBase64String(AIA.GetDerEncoded())
            );

            return aiaOid;
        }

        protected static CX509ExtensionBasicConstraints CreateBasicConstraints(bool isCA = false, bool isCritical = false)
        {
            CX509ExtensionBasicConstraints basicConstraints = new CX509ExtensionBasicConstraints();
            basicConstraints.InitializeEncode(isCA, -1);
            basicConstraints.Critical = isCritical;

            return basicConstraints;
        }
                
        protected static CX509Extension CreateCrlDistributionPoint(string crlUrl)
        {
            CObjectId crlOid = new CObjectId();
            crlOid.InitializeFromValue(CertPolicy.GetEntityOidString(CertPolicyType.CRL));
            
            CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
            crlEncode.Reset(1);
            crlEncode.SetNameCount(0, 1);
            crlEncode.SetNameEntry(0, 0, 7, crlUrl);
            string encodedCrlDistInfo = crlEncode.Encode();

            CX509Extension crl = new CX509Extension();
            crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, encodedCrlDistInfo);

            return crl;
        }

        protected static CCertificatePolicy CreateCriticalCertPolicy(string policyOid)
        {
            if (null == policyOid) return null;

            CObjectId oid = new CObjectId();
            oid.InitializeFromValue(policyOid);
            CCertificatePolicy certPolicy = new CCertificatePolicy();
            certPolicy.Initialize(oid);

            return certPolicy;
        }
        
        protected static CX509ExtensionCertificatePolicies CreateCertPolicies(params CCertificatePolicy[] policies)
        {
            // https://www.ietf.org/rfc/rfc3647.txt
            CCertificatePolicies certPolicies = new CCertificatePolicies();
            foreach (CCertificatePolicy policy in policies)
            {
                certPolicies.Add(policy);
            }

            CX509ExtensionCertificatePolicies policiesExtension = new CX509ExtensionCertificatePolicies();
            policiesExtension.InitializeEncode(certPolicies);

            return policiesExtension;
        }

        protected static bool RemoveCertFromStore(string subject, X509Store store = null)
        {
            try
            {
                if (null == store)
                {
                    store = new X509Store("My", StoreLocation.LocalMachine);
                }
                store.Open(OpenFlags.ReadWrite);

                foreach (X509Certificate2 c in store.Certificates)
                {
                    if (c.SubjectName.Name.Contains(subject))
                    {
                        store.Remove(c);
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public X509Certificate2 RetrieveCertFromStore(string subject, X509Store store = null)
        {
            try
            {
                if (null == store)
                {
                    store = new X509Store("My", StoreLocation.LocalMachine);
                }
                store.Open(OpenFlags.ReadWrite);

                foreach (X509Certificate2 c in store.Certificates)
                {
                    if (c.SubjectName.Name.Contains(subject))
                    {
                        return c;
                    }
                }
                return null;
            }
            catch
            {
                return null;
            }
        }
    }
}