using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ses.Certman
{
    internal static class Log
    {
        private static string LOGFILENAME = ConfigurationManager.AppSettings["LOGFILENAME"].ToString();
        private static string _logfile = string.Format(LOGFILENAME, DateTime.Now);

        private static string Filepath { get { return _logfile; } }
        private static object locker = new Object();

        public static void WriteToLog(StringBuilder text)
        {
            WriteToLog(text.ToString());
        }

        public static void WriteToLog(string text)
        {
            lock (locker)
            {
                using (FileStream file = new FileStream(Filepath, FileMode.Append, FileAccess.Write, FileShare.Read))
                using (StreamWriter writer = new StreamWriter(file, Encoding.Unicode))
                {
                    writer.Write(text.ToString());
                }
            }
        }


    }
}
