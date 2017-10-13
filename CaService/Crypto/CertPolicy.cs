using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace Ses.CaService.Crypto
{
    public enum CertPolicyType
    {
        BUSINESS,
        CLIENT,
        COVERED,
        CRL,
        HEALTHCARE,
        LOA_INPUT,
        ROOT,
        NULL
    }

    public static class CertPolicy
    {
        private static Dictionary<CertPolicyType, string> certPolicyStrings = new Dictionary<CertPolicyType, string>()
        {
            {CertPolicyType.NULL,               null},
            {CertPolicyType.CRL,                "OID-CRL"},
            {CertPolicyType.ROOT,               "OID-RootCertPolicy"},
            {CertPolicyType.CLIENT,             "OID-ClientCertPolicy"},

            {CertPolicyType.LOA_INPUT,          "OID-LOACertPolicy"},
            {CertPolicyType.COVERED,            "OID-CoveredEntity"},
            {CertPolicyType.HEALTHCARE,         "OID-HealthcareEntity"},
            {CertPolicyType.BUSINESS,           "OID-BusinessAssociate"},
        };

        public static string GetEntityOidString(CertPolicyType certPolicy)
        {
            if (certPolicyStrings.ContainsKey(certPolicy))
            {
                string key = certPolicyStrings[certPolicy];
                return GetOidFromConfig(key);
            }
            else
            {
                return String.Empty;
            }
        }

        public static string GetOidFromConfig(string key)
        {
            try
            {
                return (string)ConfigurationManager.AppSettings[key];
            }
            catch
            {
                return String.Empty;
            }
        }
    }
}