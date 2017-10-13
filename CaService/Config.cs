using log4net;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace Ses.CaService
{
    public class Config
    {
        private static readonly ILog _log = LogManager.GetLogger(typeof(Config));

        protected internal static string Database = ConfigurationManager.ConnectionStrings["CaServiceDbContext"].ConnectionString;

        protected internal static int CrlRevokeTimespanInMinutes = int.Parse(ConfigurationManager.AppSettings["crlRevokeTimespanInMinutes"]);

        protected internal static string CrlFilePath = ConfigurationManager.AppSettings["crlFilePath"];

        protected internal static string SubjectPostfix = ConfigurationManager.AppSettings["subjectPostfix"] ?? " - HISP managed";

        protected internal static string emailCertPrefix = ConfigurationManager.AppSettings["emailCertPrefix"] ?? "emailCert||";

        protected internal static string tlsCertPrefix = ConfigurationManager.AppSettings["tlsCertPrefix"] ?? "tlsCert||";

        protected internal static string AwsCrlRevokeSqsUrl = ConfigurationManager.AppSettings["awsCrlRevokeSqsUrl"];

        protected internal static string AwsElastiCacheUrl = ConfigurationManager.AppSettings["awsElastiCacheUrl"];

        protected internal static int AwsElastiCachePort = Convert.ToInt32(ConfigurationManager.AppSettings["awsElastiCachePort"]);

        protected internal static string TmpCertFolderPath = ConfigurationManager.AppSettings["tmpCertFolderPath"];

        protected internal static string CertUtilExePath = ConfigurationManager.AppSettings["certUtilExePath"];
        
        private static Boolean _useCache = false;
        private static Boolean _cacheVarWasSet = false;
        protected internal static Boolean CachingEnabled
        {
            get
            {
                if (!_cacheVarWasSet)
                {
                    if(!Boolean.TryParse(ConfigurationManager.AppSettings["useAwsElastiCache"], out _useCache))
                    {
                        _log.Error("AppSetting Parse Failure --> useAwsElastiCache");
                    } 
                    _cacheVarWasSet = true;
                }
                return _useCache;
            }
        }
    }
}