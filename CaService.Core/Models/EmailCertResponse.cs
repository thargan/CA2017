using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Models
{
    public class EmailCertResponse : CertResponseBase
    {
        public string EmailAddress { get; set; }

        //private List<KeyPair> _keyPairs;
        //public List<KeyPair> KeyPairs
        //{
        //    get
        //    {
        //        if (null == _keyPairs) { _keyPairs = new List<KeyPair>(); }
        //        return _keyPairs;
        //    }
        //    set
        //    {
        //        if (null == _keyPairs) { _keyPairs = new List<KeyPair>(); }
        //        value = _keyPairs;
        //    }
        //}
    }
}
