using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.CrlWriter
{
    public static class Config
    {
        public static int PollingInterval
        {
            get 
            {
                int seconds;
                if(Int32.TryParse(ConfigurationManager.AppSettings["pollingIntervalInSeconds"], out seconds))
                    return seconds * 1000;
                else
                    return 5000;
            }
        }
    }
}
