using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Ses.CaService.Crypto
{
    public enum OidType
    {
        NULL = 0,
        AIA_DOI,
        AIA_OID,
        CLIENT_AUTH,
        EMAIL_PROTECTION,
        SERVER_AUTH
    }

    public static class Oid
    {
        private static Dictionary<OidType, String> Map = new Dictionary<OidType, String>()
        {
            {OidType.NULL,               null},
            {OidType.AIA_OID,            "1.3.6.1.5.5.7.1.1"},
            {OidType.SERVER_AUTH,        "1.3.6.1.5.5.7.3.1"},
            {OidType.CLIENT_AUTH,        "1.3.6.1.5.5.7.3.2"},
            {OidType.EMAIL_PROTECTION,   "1.3.6.1.5.5.7.3.4"},
            {OidType.AIA_DOI,            "1.3.6.1.5.5.7.48.2"}
        };

        public static String GetOidString(OidType oidType)
        {
            if (Map.ContainsKey(oidType))
            {
                return Map[oidType];
            }
            else
            {
                return string.Empty;
            }
        }

        public static OidType GetTypeFromOidString(string oidString)
        {
            return Map.FirstOrDefault(x => x.Value == oidString).Key;
        }
    }
}