using Ses.CaService.Core.Models;
using Ses.CaService.Core.Queuing;
using Ses.CaService.Data;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace Ses.CrlWriter
{
    class Program
    {
        static void Main(string[] args)
        {
            EventLog _log = InitializeLog();

            int timerInterval = Config.PollingInterval;
            _log.WriteEntry("Polling Interval --> " + timerInterval + " milliseconds", EventLogEntryType.Information);


            if(args.Length > 0)
            {
                timerInterval = Int32.Parse(args[0]);
            }

            var autoResetEvent = new AutoResetEvent(false);
            var queue = new QueueManager(_log);
            var timerDelegate = new TimerCallback(queue.CheckQueue);

            Timer _stateTimer = new Timer(timerDelegate, autoResetEvent, 1000, timerInterval);

            Console.WriteLine("Press \'q\' to quit..");
            while (Console.Read() != 'q') ;
        }

        private static EventLog InitializeLog()
        {
            EventLog log;
            log = new EventLog();
            log.Source = "CrlWriter";
            log.Log = "CrlWriter";

            log.WriteEntry("Initialize CrlWriter Log");
            return log;
        }
    }
}
