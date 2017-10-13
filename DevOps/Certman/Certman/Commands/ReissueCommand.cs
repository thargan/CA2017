using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.Http;
using Newtonsoft.Json;
using System.Data.SqlClient;
using System.Configuration;
using System.Data;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;

namespace Ses.Certman.Commands
{
    public class ReissueCommand
    {
        public static StringBuilder ri(string emailAddress, string certProfileName, string accountType = "Patient", int timeToLiveInMonths=12)
        {
            return reissue(emailAddress, certProfileName, accountType, timeToLiveInMonths);
        }
        public static StringBuilder reissue(string emailAddress, string certProfileName, string accountType = "Patient", int timeToLiveInMonths = 12)
        {
            AccountType type = (AccountType)Enum.Parse(typeof(AccountType), accountType);
            return reissueCert(emailAddress, certProfileName, type, timeToLiveInMonths);
        }

        private static StringBuilder reissueCert(string emailAddress, string certProfileName, AccountType accountType, int timeToLiveInMonths = 12)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(Configuration.CAURI);
                client.DefaultRequestHeaders.Accept.Clear();

                try
                {
                    EmailUpdateCertRequest payload = new EmailUpdateCertRequest();
                    payload.TimeToLiveInMonths = timeToLiveInMonths;
                    payload.AccountType = accountType;
                    payload.CertProfileName = certProfileName;

                    var serializedContent = JsonConvert.SerializeObject(payload);
                    HttpContent content = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                    var reissueUrl = new Uri(Configuration.CAURI + "certs/email/" + emailAddress + "/reissue");
                    var response = client.PutAsync(reissueUrl, content).Result;
                    response.EnsureSuccessStatusCode();

                    return new StringBuilder(string.Format("{0}Reissued \"{1}\" with TimeToLiveInMonths={2}", Environment.NewLine, emailAddress, timeToLiveInMonths));
                }
                catch (HttpRequestException e)
                {
                    Log.WriteToLog("HttpRequestException: " + e.Message);
                    return new StringBuilder(string.Format("{0}Failed to reissue {1}!", Environment.NewLine, emailAddress));
                }
            }
        }

    }
}