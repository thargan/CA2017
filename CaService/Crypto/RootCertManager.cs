using CERTENROLLLib;
using Ses.CaService.Core.Crypto;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Ses.CaService.Crypto
{
    public class RootCertManager : BaseCertManager
    {
        public X509Certificate2 CreateRootCert(CX500DistinguishedName dn, DateTime expirationDate, string crlUrl, string rootCertPolicyOid = null, string entityCertPolicyOid = null)
        {
            string rootOid = rootCertPolicyOid ?? CertPolicy.GetEntityOidString(CertPolicyType.ROOT);
            string entityOid = entityCertPolicyOid ?? CertPolicy.GetEntityOidString(CertPolicyType.NULL);

            CX509PrivateKey key = CreatePrivateKey(KeyLength);
            CObjectId hashAlgorithm = Hashing.InitializeSecureHashAlgorithm("SHA256");
            CX509CertificateRequestCertificate rootCert = CreateSelfSignedCert(key, dn, dn, expirationDate, hashAlgorithm);

            // Extensions
            CX509ExtensionKeyUsage eku = CreateExtensionKeyUsage(CertificateType.ROOT);
            CX509ExtensionBasicConstraints basicConstraints = CreateBasicConstraints(true);
            rootCert.X509Extensions.Add((CX509Extension)eku);
            rootCert.X509Extensions.Add((CX509Extension)basicConstraints);

            // Policies
            CCertificatePolicy rootPolicy = CreateCriticalCertPolicy(rootOid);
            CCertificatePolicy entityPolicy = CreateCriticalCertPolicy(entityOid);
            CX509ExtensionCertificatePolicies certPolicies = (null == entityPolicy ? CreateCertPolicies(rootPolicy) : CreateCertPolicies(rootPolicy, entityPolicy));
            rootCert.X509Extensions.Add((CX509Extension)certPolicies);

            // CRL
            CX509Extension crl = CreateCrlDistributionPoint(crlUrl);
            rootCert.X509Extensions.Add(crl);

            string base64EncodedCert = CreateBase64EncodedPkcs12(rootCert);

            return new X509Certificate2(Convert.FromBase64String(base64EncodedCert), Password, X509KeyStorageFlags.Exportable);
        }

        private CX509CertificateRequestCertificate CreateSelfSignedCert(CX509PrivateKey key, CX500DistinguishedName subject, CX500DistinguishedName issuer, DateTime expirationDate, CObjectId hashAlgorithm)
        {
            CX509CertificateRequestCertificate selfSignedCert = CreateUnsignedCert(key, subject, expirationDate, hashAlgorithm);
            selfSignedCert.Issuer = issuer;

            return selfSignedCert;
        }
    }
}