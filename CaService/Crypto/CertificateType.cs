using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Ses.CaService.Crypto
{
    public enum CertificateType
    {
        CLIENT_ENCRYPTION_SIGNING,
        CLIENT_ENCRYPTION,
        CLIENT_SIGNING,
        INTERMEDIATE,
        ROOT,
        OCSP
    }
}