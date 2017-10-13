using CERTCLILib;
using CERTENCODELib;
using CERTENROLLLib;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Ses.CaService.Crypto
{
    public class AriCertManager
    {
        public X509Certificate2 CreateRootCert(string subject, DateTime expDate, int keylength = 2048, string crlURL = null, string entityType = null, string certPolicyOID = "1.3.6.1.4.1.41179.0.1")
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode(subject, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the publicKey
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = keylength;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy
                = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use SHA256 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(
                X509CertificateEnrollmentContext.ContextMachine,
                privateKey,
                string.Empty);
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            // extensions
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
                | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);

            // basic constraints
            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(true, -1);
            bc.Critical = false;

            cert.X509Extensions.Add((CX509Extension)bc);

            /*Add OCSP No Revocation Checking
            CObjectId noRevOid = new CObjectId();
            noRevOid.InitializeFromValue("1.3.6.1.5.5.7.48.1.5");
            CX509Extension noRev = new CX509Extension();
            noRev.Initialize(noRevOid, EncodingType.XCN_CRYPT_STRING_ANY, "");
            tlsCert.X509Extensions.Add(noRev);
            Add OCSP AIA Extension (TBD)
            CObjectId AIAOid = new CObjectId();
            AIAOid.InitializeFromValue("1.3.6.1.5.5.7.1.1");
            CX509Extension AIA = new CX509Extension();
            UriBuilder myURI = new UriBuilder("someurl");
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            System.IO.MemoryStream ms = new System.IO.MemoryStream();
            bf.Serialize(ms, myURI.Uri);
            AIA.Initialize(AIAOid, EncodingType.XCN_CRYPT_STRING_BASE64, Convert.ToBase64String(ms.ToArray()));
            tlsCert.X509Extensions.Add(AIA);*/

            //Add CRL Distribution Point if defined
            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            // Add the critical publicKey policy.
            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue(certPolicyOID);
            CCertificatePolicy cp = new CCertificatePolicy();
            cp.Initialize(cpOid);

            // Add the entity ids
            CCertificatePolicy entityCp = null;
            if (entityType != null)
            {
                CObjectId entityCpOid = new CObjectId();
                String entityOidString = "";

                if (entityType.Equals("Covered")) entityOidString = "1.3.6.1.4.1.41179.2.1";
                else if (entityType.Equals("Patient")) entityOidString = "1.3.6.1.4.1.41179.2.2";
                else if (entityType.Equals("HealthCare")) entityOidString = "1.3.6.1.4.1.41179.2.3";
                else if (entityType.Equals("Business")) entityOidString = "1.3.6.1.4.1.41179.2.4";

                entityCpOid.InitializeFromValue(entityOidString);
                entityCp = new CCertificatePolicy();
                entityCp.Initialize(entityCpOid);
            }

            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);
            if (entityCp != null) cps.Add(entityCp);
            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable

           );
        }

        public X509Certificate2 FixBadRootCert(X509Certificate2 badcert)
        {
            // Create the self signing model
            var cert = new CX509CertificateRequestCertificate();

            string raw = badcert.GetRawCertDataString();

            cert.InitializeFromCertificate(X509CertificateEnrollmentContext.ContextMachine, badcert.SerialNumber, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEXRAW, X509RequestInheritOptions.InheritPrivateKey);

            //tlsCert.InitializeFromCertificate(X509CertificateEnrollmentContext.ContextMachine, badcert.SerialNumber, EncodingType.XCN_CRYPT_STRING_HEXRAW, X509RequestInheritOptions.InheritPrivateKey);

            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode(badcert.Subject, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = badcert.NotBefore;
            cert.NotAfter = badcert.NotAfter.AddDays(1);
            cert.set_SerialNumber(CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEXRAW, badcert.SerialNumber);
            cert.X509Extensions.Clear();

            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");
            //tlsCert.HashAlgorithm = hashobj;

            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);

            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(true, -1);
            bc.Critical = false;
            cert.X509Extensions.Add((CX509Extension)bc);

            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue("1.3.6.1.4.1.41179.0.1");
            CCertificatePolicy cp = new CCertificatePolicy();
            cp.Initialize(cpOid);
            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);

            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64
            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin
            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(System.Convert.FromBase64String(base64encoded), "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2 CreateIntermediaryCert(string subject, X509Certificate2 SEScert, DateTime expDate, string crlURL = null, int keylength = 2048, string certPolicyOID = "1.3.6.1.4.1.41179.0.1")
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode(subject, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            var issuen = new CX500DistinguishedName();
            issuen.Encode(SEScert.Issuer);

            // create a new private key for the publicKey
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = keylength;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(
                X509CertificateEnrollmentContext.ContextMachine,
                privateKey,
                string.Empty);

            cert.Subject = dn;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            //take care of signingCert
            ISignerCertificate signerCertificate = new CSignerCertificate();
            signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, SEScert.GetRawCertDataString());
            cert.SignerCertificate = (CSignerCertificate)signerCertificate;

            // extensions
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
                | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);
            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(true, -1);
            bc.Critical = false;
            cert.X509Extensions.Add((CX509Extension)bc);

            //AIA
            DerObjectIdentifier myADOID = new DerObjectIdentifier("1.3.6.1.5.5.7.48.2");
            GeneralName myGN = new GeneralName(6, "http://www.directaddress.net/public/rootCA.der");
            AccessDescription ad = new AccessDescription(myADOID, myGN);
            AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(ad);
            CObjectId AIAOid = new CObjectId();
            AIAOid.InitializeFromValue("1.3.6.1.5.5.7.1.1");
            CX509Extension AIA = new CX509Extension();
            AIA.Initialize(AIAOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY, Convert.ToBase64String(authorityInfoAccess.GetDerEncoded()));
            cert.X509Extensions.Add(AIA);

            //Add CRL Distribution Point if defined
            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            // Add the publicKey policy.
            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue(certPolicyOID);
            CCertificatePolicy cp = new CCertificatePolicy();
            //CPolicyQualifier Qualifier = new CPolicyQualifier();
            //Qualifier.InitializeEncode("Policy Notice", PolicyQualifierType.PolicyQualifierTypeUserNotice);
            cp.Initialize(cpOid);
            //cp.PolicyQualifiers.Add(Qualifier);
            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);
            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",

                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public string GeneratePIN()
        {
            Random rnd = new Random();
            int pin = rnd.Next(000001, 999999);
            return pin.ToString();
        }

        public string GeneratePFX(X509Certificate2 cert, string outpath, string password = null)
        {
            if (password == null) password = GeneratePIN();

            //add some secure way of seeing GeneratedPIN
            byte[] PFX = cert.Export(X509ContentType.Pkcs12, password);
            System.IO.File.WriteAllBytes(outpath, PFX);
            return password;
        }

        public X509Certificate2 CreateClientCert(string cname, string email, X509Certificate2 SEScert, DateTime expDate,
            string crlURL = null, int keylength = 2048, string certPolicyOID = "1.3.6.1.4.1.41179.0.1.2", string loaPolicyOIDInput = "1.3.6.1.4.1.41179.1.3")
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + cname + ",E=" + email, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // This variable is never used anywhere else in the method. Do we still need it?
            var issuen = new CX500DistinguishedName();
            issuen.Encode(SEScert.Issuer);

            // create a new private key for the publicKey
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = keylength;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(
                X509CertificateEnrollmentContext.ContextMachine,
                privateKey,
                string.Empty);
            cert.Subject = dn;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            //take care of signingCert
            ISignerCertificate signerCertificate = new CSignerCertificate();
            signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, SEScert.GetRawCertDataString());
            cert.SignerCertificate = (CSignerCertificate)signerCertificate;

            // extensions
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);

            CAlternativeName altname = new CAlternativeName();
            altname.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME, email);
            CAlternativeNames altnames = new CAlternativeNames();
            altnames.Add(altname);

            CX509ExtensionAlternativeNames altnameext = new CX509ExtensionAlternativeNames();
            altnameext.InitializeEncode(altnames);
            cert.X509Extensions.Add((CX509Extension)altnameext);

            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(false, -1);
            bc.Critical = false;
            cert.X509Extensions.Add((CX509Extension)bc);

            //orgId protection
            CObjectId EkuOid = new CObjectId();
            EkuOid.InitializeFromValue("1.3.6.1.5.5.7.3.4");
            CObjectIds EkuOids = new CObjectIds();
            EkuOids.Add(EkuOid);

            CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(EkuOids);
            eku.Critical = false;
            cert.X509Extensions.Add((CX509Extension)eku);

            //AIA
            DerObjectIdentifier myADOID = new DerObjectIdentifier("1.3.6.1.5.5.7.48.2");
            GeneralName myGN = new GeneralName(6, "http://www.directaddress.net/public/intermediateCA.der");
            AccessDescription ad = new AccessDescription(myADOID, myGN);
            AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(ad);

            CObjectId AIAOid = new CObjectId();
            AIAOid.InitializeFromValue("1.3.6.1.5.5.7.1.1");
            CX509Extension AIA = new CX509Extension();
            AIA.Initialize(AIAOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY, Convert.ToBase64String(authorityInfoAccess.GetDerEncoded()));
            cert.X509Extensions.Add(AIA);

            //Add CRL Distribution Point if defined
            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            // Add the publicKey policies.
            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue(certPolicyOID);
            CCertificatePolicy cp = new CCertificatePolicy();
            //Qualifer Code not neccesary for now
            //CPolicyQualifier Qualifier = new CPolicyQualifier();
            //Qualifier.InitializeEncode("Policy Notice", PolicyQualifierType.PolicyQualifierTypeUserNotice);
            //cp.PolicyQualifiers.Add(Qualifier);
            cp.Initialize(cpOid);

            CObjectId loacpOid = new CObjectId();
            loacpOid.InitializeFromValue(loaPolicyOIDInput);
            CCertificatePolicy loacp = new CCertificatePolicy();
            loacp.Initialize(loacpOid);
            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);
            cps.Add(loacp);

            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            // and install it back as the response
            // Testing Remove the save to windows key x509Store . . . s
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2 CreateClientCertExtCA(string cname, string email, DateTime expDate, CX509PrivateKey privateKey, string CAConfigString, string crlURL = null, string certPolicyOID = "1.3.6.1.4.1.41179.0.1.2")
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + cname + ",E=" + email, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model

            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(
                X509CertificateEnrollmentContext.ContextMachine,
                privateKey,
                string.Empty);
            cert.Subject = dn;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            // extensions
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);
            CAlternativeName altname = new CAlternativeName();
            altname.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME, email);
            CAlternativeNames altnames = new CAlternativeNames();
            altnames.Add(altname);
            CX509ExtensionAlternativeNames altnameext = new CX509ExtensionAlternativeNames();
            altnameext.InitializeEncode(altnames);
            cert.X509Extensions.Add((CX509Extension)altnameext);
            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(false, -1);
            bc.Critical = false;
            cert.X509Extensions.Add((CX509Extension)bc);

            //orgId protection

            CObjectId EkuOid = new CObjectId();
            EkuOid.InitializeFromValue("1.3.6.1.5.5.7.3.4");
            CObjectIds EkuOids = new CObjectIds();
            EkuOids.Add(EkuOid);
            CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(EkuOids);
            eku.Critical = false;
            cert.X509Extensions.Add((CX509Extension)eku);

            //AIA
            DerObjectIdentifier myADOID = new DerObjectIdentifier("1.3.6.1.5.5.7.48.2");
            GeneralName myGN = new GeneralName(6, "http://www.directaddress.net/public/intermediateCA.der");
            AccessDescription ad = new AccessDescription(myADOID, myGN);
            AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(ad);
            CObjectId AIAOid = new CObjectId();
            AIAOid.InitializeFromValue("1.3.6.1.5.5.7.1.1");
            CX509Extension AIA = new CX509Extension();
            AIA.Initialize(AIAOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY, Convert.ToBase64String(authorityInfoAccess.GetDerEncoded()));
            cert.X509Extensions.Add(AIA);

            //Add CRL Distribution Point if defined
            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            // Add the publicKey policies.
            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue(certPolicyOID);
            CCertificatePolicy cp = new CCertificatePolicy();

            //Qualifer Code not neccesary for now
            //CPolicyQualifier Qualifier = new CPolicyQualifier();
            //Qualifier.InitializeEncode("Policy Notice", PolicyQualifierType.PolicyQualifierTypeUserNotice);
            //cp.PolicyQualifiers.Add(Qualifier);
            cp.Initialize(cpOid);
            CObjectId loacpOid = new CObjectId();
            loacpOid.InitializeFromValue("1.3.6.1.4.1.41179.1.3");
            CCertificatePolicy loacp = new CCertificatePolicy();
            loacp.Initialize(loacpOid);
            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);
            cps.Add(loacp);
            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            //send tlsCert to CA for sign
            CCertRequest objCertRequest = new CCertRequest();
            const int CR_BASE64 = 0x1;
            const int CR_IN_FORMATANY = 0;
            const int CR_OUT_CHAIN = 0x100;
            objCertRequest.Submit(CR_BASE64 | CR_IN_FORMATANY, csr, null, CAConfigString);
            csr = objCertRequest.GetCertificate(CR_BASE64 | CR_OUT_CHAIN);

            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",

                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2 CreateOCSPCert(string cname, X509Certificate2 SEScert, DateTime expDate, string crlURL = null, int keylength = 2048, string certPolicyOID = "1.3.6.1.4.1.41179.0.1")
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode(cname, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            var issuen = new CX500DistinguishedName();
            issuen.Encode(SEScert.Issuer);

            // create a new private key for the publicKey
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = keylength; ;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(
                X509CertificateEnrollmentContext.ContextMachine,
                privateKey,
                string.Empty);
            cert.Subject = dn;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            //take care of signingCert
            ISignerCertificate signerCertificate = new CSignerCertificate();
            signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, SEScert.GetRawCertDataString());
            cert.SignerCertificate = (CSignerCertificate)signerCertificate;

            // extensions
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE);
            ku.Critical = true;
            cert.X509Extensions.Add((CX509Extension)ku);
            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(false, -1);
            bc.Critical = false;
            cert.X509Extensions.Add((CX509Extension)bc);

            //Add CRL Distribution Point if defined
            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            /*Add OCSP
            CX509ExtensionEnhancedKeyUsage ocsp = new CX509ExtensionEnhancedKeyUsage();
            CObjectId EkuOid = new CObjectId();
            EkuOid.InitializeFromValue("1.3.6.1.5.5.7.3.9");
            CObjectIds EkuOids = new CObjectIds();
            EkuOids.Add(EkuOid);
            CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(EkuOids);
            eku.Critical = false;
            tlsCert.X509Extensions.Add((CX509Extension)eku);

            //Add OCSP No Revocation Checking
            CObjectId noRevOid = new CObjectId();
            noRevOid.InitializeFromValue("1.3.6.1.5.5.7.48.1.5");
            CX509Extension noRev = new CX509Extension();
            noRev.Initialize(noRevOid, EncodingType.XCN_CRYPT_STRING_ANY, "");
            tlsCert.X509Extensions.Add(noRev);
            */

            // Add the publicKey policy.

            CObjectId cpOid = new CObjectId();
            cpOid.InitializeFromValue(certPolicyOID);
            CCertificatePolicy cp = new CCertificatePolicy();

            //CPolicyQualifier Qualifier = new CPolicyQualifier();
            //Qualifier.InitializeEncode("Policy Notice", PolicyQualifierType.PolicyQualifierTypeUserNotice);

            cp.Initialize(cpOid);

            //cp.PolicyQualifiers.Add(Qualifier);

            CCertificatePolicies cps = new CCertificatePolicies();
            cps.Add(cp);
            CX509ExtensionCertificatePolicies cpExt = new CX509ExtensionCertificatePolicies();
            cpExt.InitializeEncode(cps);
            cert.X509Extensions.Add((CX509Extension)cpExt);

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            // and install it back as the response

            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",

                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2 RenewCert(X509Certificate2 client, X509Certificate2 root, DateTime expDate, string crlURL = null)
        {
            var oldSerialNumber = client.SerialNumber;
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            string sub = client.SubjectName.Name;
            dn.Encode(sub, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            var issuen = new CX500DistinguishedName();
            issuen.Encode(root.Issuer);

            // Use the stronger SHA256 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                "SHA256");

            // Create the self signing model

            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromCertificate(X509CertificateEnrollmentContext.ContextMachine, client.GetRawCertDataString(), CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, X509RequestInheritOptions.InheritPrivateKey);
            cert.Subject = dn;
            cert.NotBefore = client.NotBefore;
            cert.NotAfter = expDate;
            cert.HashAlgorithm = hashobj;

            cert.set_SerialNumber(CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, oldSerialNumber);

            //Add CRL Distribution Point if defined

            if (crlURL != null)
            {
                CObjectId crlOid = new CObjectId();
                crlOid.InitializeFromValue("2.5.29.31");
                CCertEncodeCRLDistInfo crlEncode = new CCertEncodeCRLDistInfo();
                crlEncode.Reset(1);
                crlEncode.SetNameCount(0, 1);
                crlEncode.SetNameEntry(0, 0, 7, crlURL);
                string disEnc = crlEncode.Encode();
                CX509Extension crl = new CX509Extension();
                crl.Initialize(crlOid, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_ANY, disEnc);
                cert.X509Extensions.Add(crl);
            }

            //take care of signingCert
            ISignerCertificate signerCertificate = new CSignerCertificate();
            signerCertificate.Initialize(true, X509PrivateKeyVerify.VerifyNone, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_HEX, root.GetRawCertDataString());
            cert.SignerCertificate = (CSignerCertificate)signerCertificate;

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the publicKey
            string csr = enroll.CreateRequest(); // Output the model in base64

            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no pin

            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty pin)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2 GetCertFromStore(string subject, StoreLocation storeLoc)
        {
            X509Store store = new X509Store("My", storeLoc);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;
            foreach (X509Certificate2 c in store.Certificates)
            {
                if (c.SubjectName.Name.Equals(subject)) cert = c;
            }

            return cert;
        }

        //returns bouncy castle crl object

        public X509Crl GenerateCRL(X509Certificate2 root)
        {
            Org.BouncyCastle.X509.X509Certificate r = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(root);
            AsymmetricKeyParameter bouncyCastlePrivateKey = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(root.PrivateKey).Private;
            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(r.IssuerDN);
            crlGen.SetSignatureAlgorithm(r.SigAlgOid);
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddDays(30));
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(r.GetPublicKey()));
            return crlGen.Generate(bouncyCastlePrivateKey);
        }

        public void RenewCRL(X509Certificate2 root, string crlFP)
        {
            X509Crl crl = GetCrlFromLocalMachine(crlFP);
            Org.BouncyCastle.X509.X509Certificate r = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(root);
            AsymmetricKeyParameter bouncyCastlePrivateKey = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(root.PrivateKey).Private;
            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(r.SubjectDN);
            crlGen.SetSignatureAlgorithm(r.SigAlgOid);
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddDays(30));
            crlGen.AddCrl(crl);
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(r.GetPublicKey()));
            ExportCRL(crlGen.Generate(bouncyCastlePrivateKey), crlFP);
        }

        public void ExportCRL(X509Crl crl, string outpath)
        {
            // If we don't control the CRL file, we can't export a new one, so just write it locally to prevent errors.
            // This should only occur for unit tests on developer boxes; make sure production boxes are configured correctly.
            if (outpath.Contains("http://"))
            {
                outpath = "./temporaryLocalCrlStore.crl";
            }
            System.IO.File.WriteAllBytes(outpath, crl.GetEncoded());
        }

        public void RevokeCert(X509Certificate2 root, X509Certificate2 cert, string crlFP)
        {
            X509Crl crl = GetCrlFromLocalMachine(crlFP);
            Org.BouncyCastle.X509.X509Certificate r = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(root);
            AsymmetricKeyParameter bouncyCastlePrivateKey = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(root.PrivateKey).Private;
            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(r.SubjectDN);
            crlGen.SetSignatureAlgorithm(r.SigAlgOid);
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddDays(30));
            crlGen.AddCrl(crl);
            Org.BouncyCastle.X509.X509Certificate c = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(cert);
            crlGen.AddCrlEntry(c.SerialNumber, DateTime.Now, CrlReason.PrivilegeWithdrawn);
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(r.GetPublicKey()));
            ExportCRL(crlGen.Generate(bouncyCastlePrivateKey), crlFP);
        }

        private X509Crl GetCrlFromLocalMachine(string filePath)
        {
            X509CrlParser crlParse = new X509CrlParser();
            return crlParse.ReadCrl(System.IO.File.ReadAllBytes(filePath));
        }
    }
}