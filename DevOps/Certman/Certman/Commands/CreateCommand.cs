using Newtonsoft.Json;
using Ses.CaService.Core;
using Ses.CaService.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Ses.Certman.Commands
{
    public class CreateCommand
    {
        private static Dictionary<AccountType, String> ProfileMap = new Dictionary<AccountType, String>()
        {
            {AccountType.NULL,               null},
            {AccountType.Patient,            Configuration.CERT_PROFILE_PATIENT},
            {AccountType.Professional,       Configuration.CERT_PROFILE_DIRECTTRUST},
            {AccountType.Organization,       Configuration.CERT_PROFILE_NONDIRECTTRUST}
        };

        public static StringBuilder c(string email,  string accountType , string certProfileName  , string nameFirst  , string nameLast ,   string city  , string state , string nameTitle=null   ,string organizationName = null)
        {
            return create(email, accountType, certProfileName, nameFirst, nameLast, city, state, nameTitle, organizationName);
             
        }

        public static StringBuilder create(string email, string accountType, string certProfileName, string nameFirst, string nameLast,   string city, string state,string nameTitle=null   , string organizationName = null)
        {
            AccountType type = (AccountType)Enum.Parse(typeof(AccountType), accountType);
            return Create(email,type, certProfileName,nameFirst,nameLast, city,state,nameTitle,organizationName);
        }
       
         
        private static StringBuilder Create(string emailAddress, AccountType accountType , string certProfileName ,string nameFirst    , string nameLast        , string city    , string state,string nameTitle=null   ,string organizationName=null   )
        
        {
            if (String.IsNullOrEmpty(certProfileName)|| String.IsNullOrEmpty(nameFirst) || String.IsNullOrEmpty(nameLast) || String.IsNullOrEmpty(city) || String.IsNullOrEmpty(state))
            {

                Log.WriteToLog("Can not create cert without certProfileName ,firstname ,lastname,city or state  ");
                return new StringBuilder(string.Format("{0}Failed to create {1}!", Environment.NewLine, emailAddress));
            }

           
           if (accountType !=AccountType.Patient && String.IsNullOrEmpty(organizationName) ){

                Log.WriteToLog("Can not create cert for a provider or organization without organnization name  "  );
                return new StringBuilder(string.Format("{0}Failed to create {1}!", Environment.NewLine, emailAddress));
           }

            EmailCreateCertRequest payload = new EmailCreateCertRequest()
            {
                Email = emailAddress,
                NameFirst =   nameFirst,
                NameLast = nameLast,
                NameTitle =  String.IsNullOrEmpty(nameTitle)?"":nameTitle,
                OrganizationName = String.IsNullOrEmpty(organizationName) ?"":organizationName  ,
                City =  city ,
                State =   state  ,
                CertProfileName =   certProfileName,
                AccountType = accountType
            };

            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(Configuration.CAURI);
                client.DefaultRequestHeaders.Accept.Clear();

                try
                {
                    var serializedContent = JsonConvert.SerializeObject(payload);
                    HttpContent content = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                    var response = client.PostAsync(new Uri(Configuration.CAURI + "certs/email/"), content).Result;
                    response.EnsureSuccessStatusCode();
                    return new StringBuilder(String.Format("{0} Generated test certificate: {1}", Environment.NewLine, emailAddress));
                }
                catch (HttpRequestException e)
                {
                    Log.WriteToLog("HttpRequestException: " + e.Message);
                    return new StringBuilder(string.Format("{0}Failed to create {1}!", Environment.NewLine, emailAddress));
                }
            }
        }

        private static String GetProfileName(AccountType accountType)
        {
            if (ProfileMap.ContainsKey(accountType))
                return ProfileMap[accountType];
            else
                return String.Empty;
        }
    }
}