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
    public class DefaultCommands
    {
        private static List<string> _readDataResults = new List<string>();
        internal static List<string> ReadDataResults
        {
            get { return _readDataResults; }
            set { _readDataResults = value; }
        }

        public static StringBuilder cf()
        {
            return config();
        }
        public static StringBuilder config()
        {
            string header = "  " + new String('-', 77);

            var result = new StringBuilder();
            result.AppendLine();
            result.AppendLine("  APP.CONFIG");
            result.AppendLine(header);
            result.AppendLine("  DATABASE    = " + Configuration.DB.Substring(Configuration.DB.IndexOf('=') + 1, (Configuration.DB.IndexOf(',') - (Configuration.DB.IndexOf('=') + 1))));
            result.AppendLine("  CAURI       = " + Configuration.CAURI);
            result.AppendLine("  LOGFILENAME = " + Configuration.LOGFILENAME);
            return result;
        }

        public static StringBuilder x()
        {
            return external();
        }
        public static StringBuilder external()
        {
            string sql = "SELECT EmailAS1 " +
                ", EncryptionCertExpDate " +
                " FROM Certificate " +
                " WHERE IsExternal = 'true' ";

            SqlCommand command = new SqlCommand(sql);

            var result = ReadData(command);
            return result;
        }

        public static StringBuilder rt() { return renewToday(); }
        public static StringBuilder renewToday()
        {    

            var result = new StringBuilder();
            RetrieveByDate(DateTime.Now, 2);

            if (ReadDataResults.Count > 0)
            {
                foreach (var r in ReadDataResults)
                {
                    try
                    {
                       // result.AppendLine(string.Format("{0}  renewing:  {1}{0}", Environment.NewLine, r));
                         StringBuilder renewString=renew(r, 12);
                         result.AppendLine(renewString.ToString());
                    }
                    catch (Exception e)
                    {
                         result.AppendLine(string.Format("exception in renewToday: {0} --> {1}", r, e));
                    }
                }
            }
            else
            {
                return result.AppendLine(string.Format("no expiring certs found for {0:d} or {1:d}.", DateTime.Now, DateTime.Now.AddDays(1)));
            }
            
            result.AppendLine("successfully renewed all certs expiring today.");
            return result;
        }

        public static StringBuilder d(DateTime dateTime, int days = 0)
        {
            return RetrieveByDate(dateTime, days);
        }
        public static StringBuilder date(DateTime dateTime, int days = 0)
        {
            return RetrieveByDate(dateTime, days);
        }
        
        public static StringBuilder e(string emailAddress) { return email(emailAddress); }
        public static StringBuilder email(string emailAddress)
        {
            SqlCommand command =
                new SqlCommand("SELECT EmailAS1, EncryptionCertExpDate, Id FROM Certificate WHERE " +
                    " EmailAS1 LIKE '%" + emailAddress + "%' " +
                    " AND (IsExternal IS NULL OR IsExternal = 'false') " +
                    " ORDER BY EncryptionCertExpDate");

            var result = ReadData(command);
            return result;
        }
        
        public static StringBuilder r(string emailAddress, int timeToLiveInMonths)
        {
            return renew(emailAddress, timeToLiveInMonths);
        }
        public static StringBuilder renew(string emailAddress, int timeToLiveInMonths=12)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(Configuration.CAURI);
                client.DefaultRequestHeaders.Accept.Clear();
                
                try
                {
                    EmailUpdateCertRequest payload = new EmailUpdateCertRequest();
                    payload.TimeToLiveInMonths = timeToLiveInMonths;
                    var serializedContent = JsonConvert.SerializeObject(payload);
                    HttpContent content = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                    var response = client.PutAsync(new Uri(Configuration.CAURI + "certs/email/"+ emailAddress + "/renew"), content).Result;
                    response.EnsureSuccessStatusCode();
                   
                    EmailCertResponse certResponse = JsonConvert.DeserializeObject<EmailCertResponse>(response.Content.ReadAsStringAsync().Result);
                    if (!certResponse.CacheInvalidated)
                    {   HttpContent newContent = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                         var inValidationResponse = client.PutAsync(new Uri(Configuration.CAURI + "certs/email/"+ emailAddress + "/invalidate"), newContent).Result;
                         inValidationResponse.EnsureSuccessStatusCode();
                         bool result = JsonConvert.DeserializeObject<bool>(inValidationResponse.Content.ReadAsStringAsync().Result);
                         if (!result)
                          { 
                             return new StringBuilder(string.Format("{0}Renewed : \"{1}\" with TimeToLiveInMonths={2} :Cache Invalidation Failed : {1}  ", Environment.NewLine, emailAddress, timeToLiveInMonths ));
                    
                          }
                          else { 
                                return new StringBuilder(string.Format("{0}Renewed : \"{1}\" with TimeToLiveInMonths={2}", Environment.NewLine, emailAddress, timeToLiveInMonths));
                          }



                      }
                      else { 
                            return new StringBuilder(string.Format("{0}Renewed : \"{1}\" with TimeToLiveInMonths={2}", Environment.NewLine, emailAddress, timeToLiveInMonths));
                      }
                }
                catch (HttpRequestException e)
                {
                    return new StringBuilder(string.Format("{0}Failed to renew {1}!", Environment.NewLine, emailAddress));
                    throw e;
                }
            }
        }

        public static StringBuilder FlushCache()
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(Configuration.CAURI);
                client.DefaultRequestHeaders.Accept.Clear();
                
                try
                {
                    var serializedContent = JsonConvert.SerializeObject("");
                    HttpContent content = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                    var response = client.PutAsync( new Uri(Configuration.CAURI + "certs/email/flushCache" ),content ).Result;
                    response.EnsureSuccessStatusCode(); 
                    bool result = JsonConvert.DeserializeObject<bool>(response.Content.ReadAsStringAsync().Result);
                    if (!result)
                    { 
                         return new StringBuilder(string.Format("{0} Cache Flush Failed :", Environment.NewLine ));
                    
                    }else
                    { 
                          return new StringBuilder(string.Format("{0} Cache Flushed Successfully :", Environment.NewLine ));
                    }

                      
                }
                catch (HttpRequestException e)
                {
                    return new StringBuilder(string.Format("{0} Cache Flush Failed :", Environment.NewLine ));
                    throw e;
                }
            }
        }
        
        public static StringBuilder buk(string domain) { return bulkUpdateKeyspec(domain); }
        public static StringBuilder bulkUpdateKeyspec(string domain)
        {
            var result = new StringBuilder();
            RetrieveByDomain(domain);
            int failed = 0;
            if (ReadDataResults.Count > 0)
            {
                foreach (var email in ReadDataResults)
                {
                    try
                    {
                        result.AppendLine(string.Format("{0}  updating keyspec:  {1}{0}", Environment.NewLine, email));
                        updateKyespec(email);
                    }
                    catch (Exception e)
                    {
                        result.AppendLine(string.Format("Failed to update Kyespec: {0} --> {1}", email, e));
                        failed++;
                    }
                }
            }
            else
            {
                return result.AppendLine(string.Format("no certs found for {0}.", domain));
            }

            result.AppendLine(string.Format("successfully updated {0} certs for {1}.", ReadDataResults.Count - failed, domain));
            return result;
        }

        public static StringBuilder uk(string emailAddress)
        {
            return updateKyespec(emailAddress);
        }
        public static StringBuilder updateKyespec(string emailAddress, int timeToLiveInMonths = 12)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri(Configuration.CAURI);
                client.DefaultRequestHeaders.Accept.Clear();

                try
                {
                    EmailUpdateCertRequest payload = new EmailUpdateCertRequest();
                    payload.TimeToLiveInMonths = timeToLiveInMonths;
                    payload.CertProfileName = "Provider/DirectTrust";
                    var serializedContent = JsonConvert.SerializeObject(payload);
                    HttpContent content = new StringContent(serializedContent, Encoding.UTF8, "application/json");
                    var response = client.PutAsync(new Uri(Configuration.CAURI + "certs/email/" + emailAddress + "/keyspec"), content).Result;
                    response.EnsureSuccessStatusCode();

                    return new StringBuilder(string.Format("{0}Updated \"{1}\" with Key Spec KEYEXCHANGE", Environment.NewLine, emailAddress));
                }
                catch (HttpRequestException e)
                {
                    return new StringBuilder(string.Format("{0}Failed to update keyspec {1}!", Environment.NewLine, emailAddress));
                    throw e;
                }
            }
        }

        private static StringBuilder RetrieveByDate(DateTime dateTime, int days)
        {
            var sqlFormattedDate = dateTime.ToString("yyyy-MM-dd HH:mm:ss");

            string sql = "SELECT EmailAS1 " +
                ", EncryptionCertExpDate " +
                ", DATEDIFF(day, '" + sqlFormattedDate + "', EncryptionCertExpDate) as diff " +
                " FROM Certificate " +
                " WHERE DATEDIFF(day, '" + sqlFormattedDate + "', EncryptionCertExpDate) BETWEEN 0 AND " + days +
                " AND (IsExternal IS NULL OR IsExternal = 'false') " +
                " ORDER BY EncryptionCertExpDate";

            SqlCommand command = new SqlCommand(sql);

            var result = ReadData(command);
            return result;
        }

        private static void RetrieveByDomain(string domain)
        {
            string sql = "SELECT EmailAS1 " +
                " FROM Certificate " +
                " WHERE EmailAS1 like '%@" + domain + "'";

            SqlCommand command = new SqlCommand(sql);
            using (SqlConnection connection = new SqlConnection(Configuration._connectionString))
            {
                command.Connection = connection;
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                if (reader.HasRows)
                {
                    while (reader.Read())
                    {
                        ReadDataResults.Add(reader.GetString(0));
                    }
                }
                reader.Close();
            }
        }

        private static StringBuilder ReadData(SqlCommand command)
        {
            ReadDataResults = new List<string>();

            var result = new StringBuilder();

            using (SqlConnection connection = new SqlConnection(Configuration._connectionString))
            {
                command.Connection = connection;
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                if (reader.HasRows)
                {
                    result.AppendLine();
                    result.AppendLine(String.Format("{0,44}    {1}", "EMAIL ADDRESS".PadRight(40), "EXPIRES ON"));

                    while (reader.Read())
                    {
                        ReadDataResults.Add(reader.GetString(0));
                        var e = new string(reader.GetString(0).Take(40).ToArray());
                        if (reader.GetString(0).Length > 40)
                        {
                            e = e.Substring(0, 37) + "...";
                        }
                        var date = reader.GetDateTime(1);
                        result.AppendLine(String.Format("{0,44}    {1:MM/dd/yyyy}", e.PadRight(40), date));
                    }
                }
                else
                {
                    return result.AppendLine("No results returned.");
                }
                reader.Close();
                result.AppendLine();
                result.AppendLine(string.Format("{0,3} {1}", ReadDataResults.Count, (ReadDataResults.Count == 1 ? "result." : "results.")));
                return result;
            }
        }



       
    }
}