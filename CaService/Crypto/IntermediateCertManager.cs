using CERTENROLLLib;
using Org.BouncyCastle.Asn1.X509;
using Ses.CaService.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Ses.CaService.Crypto
{
    public class IntermediateCertManager : BaseCertManager
    {
        public X509Certificate2 CreateIntermediateCert(CX500DistinguishedName dn, X509Certificate2 signingCert, DateTime expirationDate, string crlUrl, string aiaPath, string clientCertPolicyOid)
        {
            string certPolicyOid = clientCertPolicyOid ?? CertPolicy.GetEntityOidString(CertPolicyType.CLIENT);

            CX509PrivateKey key = CreatePrivateKey(KeyLength);
            CObjectId hashAlgorithm = Hashing.InitializeSecureHashAlgorithm("SHA256");
            CX509CertificateRequestCertificate intermediateCert = CreateSignedCert(key, dn, signingCert, expirationDate, hashAlgorithm);

            // Extensions
            CX509ExtensionKeyUsage eku = CreateExtensionKeyUsage(CertificateType.INTERMEDIATE);
            CX509ExtensionBasicConstraints basicConstraints = CreateBasicConstraints();
            AuthorityInformationAccess aia = CreateAuthorityInformationAccess(OidType.AIA_DOI, aiaPath);
            CX509Extension aiaOid = CreateAiaOid(OidType.AIA_OID, aia);

            // Policies
            intermediateCert.X509Extensions.Add((CX509Extension)eku);
            intermediateCert.X509Extensions.Add((CX509Extension)basicConstraints);
            intermediateCert.X509Extensions.Add(aiaOid);

            // Critical Certificate policies
            CCertificatePolicy criticalCertPolicy = CreateCriticalCertPolicy(certPolicyOid);
            CX509ExtensionCertificatePolicies certPolicies = CreateCertPolicies(criticalCertPolicy);
            intermediateCert.X509Extensions.Add((CX509Extension)certPolicies);
            
            // CRL
            CX509Extension crl = CreateCrlDistributionPoint(crlUrl);
            intermediateCert.X509Extensions.Add(crl);

            string base64EncodedCertificate = CreateBase64EncodedPkcs12(intermediateCert);

            return new X509Certificate2(Convert.FromBase64String(base64EncodedCertificate), Password, X509KeyStorageFlags.Exportable);
        }
    }
}