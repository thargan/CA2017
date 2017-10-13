using System;
using System.Web.Http;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Ses.CaService.Core;
using Ses.CaService.Core.Models;
using Ses.CaService.Core.Queuing;
using Ses.CaService.Data;
using Ses.CaService.Caching;
using Ses.CaService.Crypto;

namespace Ses.CaService.Controllers
{
    public class BaseController : ApiController
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(BaseController));

        protected static ClientCertManager ccm = new ClientCertManager();

        private static string _databaseName = Config.Database.Substring((Config.Database.IndexOf('=') + 1), (Config.Database.IndexOf(',') - Config.Database.IndexOf('=')) - 1);
        protected static string DatabaseName
        {
            get { return _databaseName; }
        }

        private ElastiCacheClient _cache;
        protected ElastiCacheClient Cache
        {
            get
            {
                if (_cache == null)
                {
                    _cache = ElastiCacheClientFactory.GetClient();
                }
                return _cache;
            }
        }

        private CaServiceDbContext _db;
        protected CaServiceDbContext db
        {
            get
            {
                if (_db == null)
                {
                    _db = new CaServiceDbContext();
                }
                return _db;
            }
        }

        protected string _route;
        protected string _key;

        protected TextHttpActionResult NotFound(string message)
        {
            return new TextHttpActionResult(message, Request);
        }

        protected static string GeneratePin()
        {
            Random rnd = new Random();
            int pin = rnd.Next(000001, 999999);
            return pin.ToString();
        }

        protected Boolean AnyAreNotNull(params string[] dnStrings)
        {
            foreach (string s in dnStrings)
            {
                if (!string.IsNullOrWhiteSpace(s)) return true;
            }

            return false;
        }

        protected Boolean AllAreNotNull(params string[] dnStrings)
        {
            foreach (string s in dnStrings)
            {
                if (string.IsNullOrWhiteSpace(s)) return false;
            }

            return true;
        }

        protected X509Certificate2 RetrieveSigningCert(string x509SerialNumber)
        {
            X509Certificate2 signingCert = null;
            X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            x509Store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCollection = (X509Certificate2Collection)x509Store.Certificates;

            foreach (X509Certificate2 x509 in storeCollection)
            {
                if (x509.SerialNumber.ToUpper() == x509SerialNumber.ToUpper())
                {
                    signingCert = x509;
                    break;
                }
            }
            return signingCert;
        }
        
        protected CertificateProfile FetchCertificateProfileFromDb(string certProfileName)
        {   
            return db.CertificateProfiles.Where(e => e.ProfileName == certProfileName).FirstOrDefault();
        }
         protected bool CacheFlush()
        {
            try
            {
                if (!Config.CachingEnabled) return false;
                return Cache.Flush();
            }
            catch(Exception ex)
            {
                _log.Error(string.Format("CacheFlush Failure: --> Exception thrown: {0}",  ex));
                return false;
            }
        }
		
        protected bool CacheDelete(string key)
        {
            key=key.ToLower();
            try
            {
                if (!Config.CachingEnabled) return false;
                return Cache.Delete(key);
            }
            catch(Exception ex)
            {
                _log.Error(string.Format("CacheDelete Failure: {0} --> Exception thrown: {1}", key, ex));
                return false;
            }
        }

        protected byte[] CacheGet(string key)
        {
            key=key.ToLower();
            try
            {
                if (!Config.CachingEnabled) return null;
                return Cache.Get(key);
            }
            catch(Exception ex)
            {
                _log.Error(string.Format("CacheGet Failure: {0} --> Exception thrown: {1}", key, ex));
                return null;
            }
        }

        protected bool CacheSet(string key, byte[] value)
        {
             key=key.ToLower();
            try
            {
                if (!Config.CachingEnabled) return false;
                return Cache.Set(key, value);
            }
            catch(Exception ex)
            {
                _log.Error(string.Format("CacheSet Failure: {0} --> Exception thrown: {1}", key, ex));
                return false;
            }
        }

        protected void RevokeCertificate(X509Certificate2 certToRevoke, string signingCertSerialNumber, string certToRevokeEmail, string certToRevokeOrgId="", bool isDelete=false)
        {
            var message = new CrlRevokeMessage()
            {
                Certificate = certToRevoke,
                CertSerialNumber = certToRevoke.SerialNumber,
                SigningCertSerialNumber = signingCertSerialNumber,
                IsDelete = isDelete
            };

            if (!String.IsNullOrWhiteSpace(certToRevokeOrgId))
            {
                message.OrgId = certToRevokeOrgId;
            }
            else
            {
                message.EmailAddress = certToRevokeEmail;
            }
            var queue = new SqsHelper();
            string msgType = isDelete ? "Delete" : "Revoke";
            _log.Debug(String.Format("> Enqueuing SQS message --> {0} Certificate: {1} with SigningCert: {2}", msgType, certToRevoke.SerialNumber, signingCertSerialNumber));

            queue.EnqueueCrlRevokeMsg(message);
        }
    }
}