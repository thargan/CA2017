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
    public class HelpCommand
    {
        //To get help use Help certman help
        private static Dictionary<string, string> _commands = new Dictionary<string, string>
        {
            {" x | external", "lists external certs."},
            {" d | date [mm/dd/yyy] <days>", "lists certs where expiry in date range."},
            {"cf | config", "displays application configuration."},
            {" e | email [match]", "lists certs where email like [match]."},
            {" q | quit", "closes the application."},
            {" c | create [email] [accountType] [certProfileName] [nameFirst] [nameLast] [nameTitle] <organizationName> ", "creates cert for [email]."},
            {" r | renew [email] <months>", "renews cert."},
            {"ri | reissue [email] [certProfileName] <accountType> <months>", "reissues cert."},
            {"rt | renewToday", "updates certs expiring within the next two days."},
            {"createcerts  | createcerts [filename]","create certs from a csv file" },
            {"csv record ex.","email,accountType,certProfileName,nameFirst,nameLast,city,state, , " }

        };

        
        public static StringBuilder help()
        {
            string header = "  " + new String('-', 77);
            string helpText = string.Join(Environment.NewLine, _commands.Select(x => String.Format("  {0}: {1}", x.Key, x.Value)).OrderBy(x => x));
            return new StringBuilder(string.Format("{0}  HELP{0}{1}{0}{2}{0}{0}", Environment.NewLine, header, helpText));
        }
    }
}