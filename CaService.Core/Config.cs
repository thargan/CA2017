using System;
using System.Configuration;

namespace Ses.CaService.Core
{
    public class Config
    {
        public static String AwsCrlRevokeSqsUrl = ConfigurationManager.AppSettings["awsCrlRevokeSqsUrl"];

        public static String crlFilePath = ConfigurationManager.AppSettings["crlFilePath"];
    }
}