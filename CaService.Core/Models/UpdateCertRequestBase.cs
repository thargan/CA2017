using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public class UpdateCertRequestBase
    {
        private string _country = null;
        protected string DefaultCountry = "US";
        public string Country
        {
            get
            {
                if (string.IsNullOrEmpty(_country))
                {
                    _country = DefaultCountry;
                }
                return _country;
            }
            set { _country = value; }
        }
        public string City { get; set; }
        public string State { get; set; }
        
        private int _timeToLiveInMonths = -1;
        protected int DefaultTimeToLiveInMonths = 12;
        
        [Range(1, 36, ErrorMessage = "TimeToLiveInMonths >= 1 and <= 36")]
        public int TimeToLiveInMonths
        {
            get
            {
                if (_timeToLiveInMonths == -1)
                {
                    _timeToLiveInMonths = DefaultTimeToLiveInMonths;
                }
                return _timeToLiveInMonths;
            }
            set { _timeToLiveInMonths = value; }
        }

        public string OrganizationName { get; set; }

        public string CertProfileName { get; set; }

        public bool IsReissue { get; set; }

        public bool IsUpdateKeyspec { get; set; }

        public string ModifiedBy { get; set; }
    }
}