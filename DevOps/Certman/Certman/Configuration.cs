using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.Certman
{
    internal class Configuration
    {
        internal static string CAURI = ConfigurationManager.AppSettings["CAURI"].ToString();
        internal static string LOGFILENAME = ConfigurationManager.AppSettings["LOGFILENAME"].ToString();
        internal static string CERT_PROFILE_DIRECTTRUST = ConfigurationManager.AppSettings["CERT_PROFILE_DIRECTTRUST"].ToString();
        internal static string CERT_PROFILE_NONDIRECTTRUST = ConfigurationManager.AppSettings["CERT_PROFILE_NONDIRECTTRUST"].ToString();
        internal static string CERT_PROFILE_NONDIRECTTRUST_IDP = ConfigurationManager.AppSettings["CERT_PROFILE_NONDIRECTTRUST_IDP"].ToString();
        internal static string CERT_PROFILE_TLS = ConfigurationManager.AppSettings["CERT_PROFILE_TLS"].ToString();
        internal static string CERT_PROFILE_PATIENT_IDP = ConfigurationManager.AppSettings["CERT_PROFILE_PATIENT_IDP"].ToString();
        internal static string CERT_PROFILE_PATIENT = ConfigurationManager.AppSettings["CERT_PROFILE_PATIENT"].ToString();

        internal static string DB = ConfigurationManager.ConnectionStrings["CertDB"].ConnectionString;

        internal static string _logfile = string.Format(LOGFILENAME, DateTime.Now);

        internal static string _connectionString = ConfigurationManager.ConnectionStrings["CertDB"].ConnectionString;
    }
}
