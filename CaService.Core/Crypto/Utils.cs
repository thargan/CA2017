using CERTENROLLLib;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Crypto
{
    public static class Utils
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(Utils));

        public static string ParseDataFromSubject(string subject, string attribute)
        {
            Regex regex = new Regex(attribute + "=(.*)");
            Match match = regex.Match(subject);

            if (match.Success)
            {
                var data = match.Groups[1].Value;
                return data.Split(',')[0];
            }
            return null;
        }

        public static string BuildCommonName(string first, string last, string title = "")
        {
            if (String.IsNullOrWhiteSpace(title))
                return string.Format("{0} {1}", first, last);
            else
                return string.Format("{0} {1} {2}", title, first, last);
        }

        public static X509Certificate2 RetrieveIssuingCertificate(string issuerSubject)
        {
            X509Certificate2 signingCert = null;
            X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            x509Store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCollection = (X509Certificate2Collection)x509Store.Certificates;

            foreach (X509Certificate2 x509 in storeCollection)
            {
                if (x509.Subject == issuerSubject)
                {
                    signingCert = x509;
                    break;
                }
            }

            if (null == signingCert) return null;

            return signingCert;
        }

        public static X509Certificate2 RetrieveIssuingCertificatByCN(string issuerCN)
        {
            X509Certificate2 signingCert = null;
            X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            x509Store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCollection = (X509Certificate2Collection)x509Store.Certificates;

            foreach (X509Certificate2 x509 in storeCollection)
            {
                string cn = DnFields.getValByAttributeTypeFromIssuerDN(x509.Subject, "cn");
                if (cn!= null)
                {
                    if (String.Equals(cn, issuerCN))
                    {
                        signingCert = x509;
                        break;
                    }
                } 
            }

            if (null == signingCert) return null;

            return signingCert;
        }

        public static bool RevokeCert(X509Certificate2 issuingCert, X509Certificate2 certToRevoke, string crlPath)
        {
            X509Crl crl = GetCrlFromLocalMachine(crlPath);
            Org.BouncyCastle.X509.X509Certificate issuer = DotNetUtilities.FromX509Certificate(issuingCert);
            AsymmetricKeyParameter privateKey = DotNetUtilities.GetKeyPair(issuingCert.PrivateKey).Private;

            var crlNumber = IncrementCrlNumber(crl);

            X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
            crlGenerator.SetIssuerDN(issuer.SubjectDN);
            crlGenerator.SetSignatureAlgorithm(issuer.SigAlgOid);
            crlGenerator.SetThisUpdate(DateTime.Now);
            crlGenerator.SetNextUpdate(DateTime.Now.AddDays(30));
            crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(crlNumber));
            crlGenerator.AddCrl(crl);

            Org.BouncyCastle.X509.X509Certificate x509Cert = DotNetUtilities.FromX509Certificate(certToRevoke);
            crlGenerator.AddCrlEntry(x509Cert.SerialNumber, DateTime.Now, CrlReason.PrivilegeWithdrawn);
            crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuer.GetPublicKey()));

            ExportCrl(crlGenerator.Generate(privateKey), crlPath);
            return true;
        }

        public static void ExportCrl(X509Crl crl, string outpath)
        {
            System.IO.File.WriteAllBytes(outpath, crl.GetEncoded());
        }

        public static X509Crl GetCrlFromLocalMachine(string filePath)
        {
            X509CrlParser crlParse = new X509CrlParser();

            return crlParse.ReadCrl(System.IO.File.ReadAllBytes(filePath));
        }

        private static BigInteger IncrementCrlNumber(X509Crl crl)
        {
            var crlNumber = new BigInteger("5000"); // default value if CRL Number not found
            var crlNumberAsAsn1OctetString = crl.GetExtensionValue(X509Extensions.CrlNumber);
            if (null != crlNumberAsAsn1OctetString)
            {
                var crlNumberAsAsn1Object = X509ExtensionUtilities.FromExtensionValue(crlNumberAsAsn1OctetString);
                crlNumber = new BigInteger(crlNumberAsAsn1Object.ToString());
            }
            crlNumber = crlNumber.Add(new BigInteger("1"));
            return crlNumber;
        }

        public static string BuildCrlFilePath(X509Certificate2 cert, string crlFilePathRoot)
        {
            string crlFileName = InterrogateCertForCrlDistributionPoint(cert);
            var splitCrlUrl = crlFileName.Split('/');
            crlFileName = splitCrlUrl[splitCrlUrl.Length - 1];
            var crlFilePath = crlFilePathRoot + crlFileName;

            return crlFilePath;
        }

        public static string InterrogateCertForAiaPath(X509Certificate2 cert)
        {
            var x509Ext = cert.Extensions.Cast<System.Security.Cryptography.X509Certificates.X509Extension>().FirstOrDefault(e => e.Oid.Value == "1.3.6.1.5.5.7.1.1");
            if (x509Ext == null || x509Ext.RawData == null || x509Ext.RawData.Length < 11)
            {
                return String.Empty;
            }

            byte[] extension_bytes = x509Ext.RawData;
            AsnEncodedData asndata = new AsnEncodedData(extension_bytes);
            string aiaData = Encoding.UTF8.GetString(extension_bytes);
            int begin = aiaData.IndexOf("http");
            int end = aiaData.Length;

            char[] urlAsCharArray = new char[end - begin];
            aiaData.CopyTo(begin, urlAsCharArray, 0, end - begin);

            return new string(urlAsCharArray); ;
        }

        public static string InterrogateCertForCrlDistributionPoint(X509Certificate2 cert)
        {
            var x509Ext = cert.Extensions.Cast<System.Security.Cryptography.X509Certificates.X509Extension>().FirstOrDefault(e => e.Oid.Value == "2.5.29.31");
            if (x509Ext == null || x509Ext.RawData == null || x509Ext.RawData.Length < 11)
            {
                return String.Empty;
            }

            byte[] extension_bytes = x509Ext.RawData;
            AsnEncodedData asndata = new AsnEncodedData(extension_bytes);
            string crlData = Encoding.UTF8.GetString(extension_bytes);
            int begin = crlData.IndexOf("http");
            int end = crlData.IndexOf(".crl") + 4;

            // logic to support old certs with bad CrlDistributionPoint
            if (end == 3)
            { 
                return "http://directaddress.net/crl";
            }

            char[] urlAsCharArray = new char[end - begin];
            crlData.CopyTo(begin, urlAsCharArray, 0, end - begin);
            
            return new string(urlAsCharArray);;
        }



        public static bool UpdateCrlDate(string crlPath)
        {
            _log.InfoFormat("Starting to check crl file  {0} for update ", crlPath);
            try
            {
                X509Crl crl = GetCrlFromLocalMachine(crlPath);
                if (crl == null)
                {
                    _log.ErrorFormat("Could not create  crl object from  file  {0}  ", crlPath);
                    return false;


                }
                if ((crl.NextUpdate.Value>DateTime.Now.AddHours(48)))
                {
                    _log.InfoFormat(" Crl file {0} update date is more then 48 hours away so not updating ", crlPath);
                    return false;
                }

                Org.BouncyCastle.Asn1.X509.X509Name cert = crl.IssuerDN;
                string cn = DnFields.getValByAttributeTypeFromIssuerDN(crl.IssuerDN.ToString(), "cn");
                if (cn == null)
                {
                    _log.InfoFormat(" Crl file {0} issuer cert's DN {1}  has no CN", crlPath, crl.IssuerDN.ToString());
                    return false;
                }

                //Get signing cert from the store 
                X509Certificate2 issuingCert = RetrieveIssuingCertificatByCN(cn);
                if (issuingCert == null)
                {
                    _log.InfoFormat(" Crl file {0} issuer cert  with DN {1}  not found in the store.Can not update the crl", crlPath, crl.IssuerDN.ToString());
                    return false;

                }

                _log.InfoFormat(" Crl file {0} issuer cert  with DN {1}   found in the store.Updating the crl", crlPath, crl.IssuerDN.ToString());

                try
                {

                    Org.BouncyCastle.X509.X509Certificate issuer = DotNetUtilities.FromX509Certificate(issuingCert);
                    AsymmetricKeyParameter privateKey = DotNetUtilities.GetKeyPair(issuingCert.PrivateKey  ).Private;

                    var crlNumber = IncrementCrlNumber(crl);
                    X509V2CrlGenerator crlGenerator = new X509V2CrlGenerator();
                    crlGenerator.SetIssuerDN(issuer.SubjectDN);
                    crlGenerator.SetSignatureAlgorithm(issuer.SigAlgOid);
                    crlGenerator.SetThisUpdate(DateTime.Now);
                    crlGenerator.SetNextUpdate(DateTime.Now.AddDays(30));
                    crlGenerator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(crlNumber));
                    crlGenerator.AddCrl(crl);

                    ExportCrl(crlGenerator.Generate(privateKey), crlPath);
                    _log.InfoFormat("Updated Crl file :{0} ", crlPath );
                    return true;
                }

                catch (Exception ex)
                {

                    _log.Error(String.Format("Encountered error while  trying to update crl  file {0} ", crlPath), ex );
                    return false;

                }

            } 
            catch(Exception e){

                _log.Error(String.Format("Encountered error while  trying to check for crl file {0} update", crlPath), e);
                 
                return false;

            }
    }
    }
}
