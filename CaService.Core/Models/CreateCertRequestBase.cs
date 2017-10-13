using System;
using System.ComponentModel.DataAnnotations;

namespace Ses.CaService.Core.Models
{
    public abstract class CreateCertRequestBase
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

        [Required(ErrorMessage = "City is required")]
        public string City { get; set; }

        [Required(ErrorMessage = "State is required")]
        public string State { get; set; }

        public int DefaultTimeToLiveInMonths = 12;
        private int _timeToLiveInMonths = -1;

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

        [Required(ErrorMessage = "CertProfileName is required")]
        public string CertProfileName { get; set; }

        public string CreatedBy { get; set; }
    }
}