using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Models
{
    public abstract class CertResponseBase
    {
        public string Href { get; set; }
        public string CertProfileName { get; set; }
        public string EffectiveDate { get; set; }
        public string ExpirationDate { get; set; }
        public string Subject { get; set; }
        public string CrlUrl { get; set; }
        public string AiaPath { get; set; }
         public bool CacheInvalidated  { get; set; }
        private List<KeyPair> _keyPairs;
        public List<KeyPair> KeyPairs
        {
            get
            {
                if(null == _keyPairs) { _keyPairs = new List<KeyPair>(); }
                return _keyPairs;
            }
            set
            {
                if (null == _keyPairs) { _keyPairs = new List<KeyPair>(); }
                value = _keyPairs;
            }
        }


        private CertificateIssuer _issuer;
        public CertificateIssuer Issuer
        {
            get
            {
                if (null == _issuer) _issuer = new CertificateIssuer();

                return _issuer;
            }
            set { _issuer = value; }
        }
    }

    public class KeyPair
    {
        public KeyPair(KeyPairType type)
        {
            Type = type;
        }

        [JsonConverter(typeof(StringEnumConverter))]
        public KeyPairType Type { get; private set; }

        public string SerialNumber { get; set; }
        public string Thumbprint { get; set; }
    }

    public class CertificateIssuer
    {
        private string _subject = String.Empty;
        public string Subject
        {
            get { return _subject; }
            set { _subject = value; }
        }

        private string _serialNumber = String.Empty;
        public string SerialNumber
        {
            get { return _serialNumber; }
            set { _serialNumber = value; }
        }
    }
}
