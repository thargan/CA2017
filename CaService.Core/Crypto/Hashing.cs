using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CERTENROLLLib;

namespace Ses.CaService.Core.Crypto
{
    public static class Hashing
    {        
        /// <summary>
        /// Creates an initialized CERTENROLLLib.CObjectId using the specified algorithmName
        /// </summary>
        public static CObjectId InitializeSecureHashAlgorithm(string algorithmName = "SHA256")
        {
            // For the full list of algorithm names see...
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375534(v=vs.85).aspx

            var secureHashAlgorithm = new CObjectId();
            secureHashAlgorithm.InitializeFromAlgorithmName(
                ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone,
                algorithmName);

            return secureHashAlgorithm;
        }
    }
}
