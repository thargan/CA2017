using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Ses.CrlWriter.Service
{
    public partial class CrlTimer : ServiceBase
    {
        private EventLog _log;
        private Timer _stateTimer;

        public CrlTimer()
        {
            _log = new EventLog();
            _log.Source = "CrlWriter Service";
            _log.Log = "CrlWriter";

            _log.WriteEntry("Initialize CrlTimer");
        }

        protected override void OnStart(string[] args)
        {
            _log.WriteEntry("OnStart", EventLogEntryType.Information);
            
            try
            {
                var autoResetEvent = new AutoResetEvent(false);
                var queue = new QueueManager(_log);
                var timerDelegate = new TimerCallback(queue.CheckQueue);

                _stateTimer = new Timer(timerDelegate, autoResetEvent, 1000, Config.PollingInterval);
            }
            catch (Exception ex)
            {   
                _log.WriteEntry(ex.ToString(), EventLogEntryType.Error);
                _stateTimer.Dispose();
                this.ExitCode = 1;
                this.Stop();
            }
        }

        protected override void OnStop()
        {
            _log.WriteEntry("CRL Writer Service Stop");
        }
    }
}
