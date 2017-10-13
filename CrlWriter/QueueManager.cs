using Ses.CaService.Core.Models;
using Ses.CaService.Core.Queuing;
using Ses.CaService.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace Ses.CrlWriter
{
    public class QueueManager
    {
        private EventLog _log = new EventLog();

        public QueueManager(EventLog log = null)
        {
            if (null != log) _log = log;
        }

        public void CheckQueue(Object stateInfo)
        {
            try
            {
                var autoResetEvent = stateInfo as AutoResetEvent;
                var queue = new SqsHelper();
                _log.WriteEntry("Check Queue --> " + queue.SqsConfig.ServiceURL, EventLogEntryType.Information);

                CrlRevokeMessage message = queue.DequeueCrlRevokeMsg();
                if (null == message)
                {
                    _log.WriteEntry("NO SQS MESSAGES FOUND", EventLogEntryType.Warning);
                    autoResetEvent.Set();

                    return;
                }
                string msgType = message.IsDelete ? "DELETE" : "REVOKE";
                _log.WriteEntry(msgType + " MESSAGE DEQUEUED --> " + (message.EmailAddress ?? message.OrgId), EventLogEntryType.Information);

                CertificateHelper certHelper = new CertificateHelper();
                X509Certificate2 signingCert = certHelper.RetrieveSigningCertificate(message.SigningCertSerialNumber);
                X509Certificate2 certToRevoke = message.Certificate;
                string certType = String.Empty;
                string id = String.Empty;
                if (null == message.EmailAddress)
                {
                    certType = "TLS";
                    id = message.OrgId;
                }
                else
                {
                    certType = "EMAIL";
                    id = message.EmailAddress;
                }
                _log.WriteEntry(String.Format("PROCESSING {0} {1} CERT --> {2}", msgType, certType, id), EventLogEntryType.Information);

                var crlFilePathRoot = ConfigurationManager.AppSettings["crlFilePath"];
                var crlFilePath = Utils.BuildCrlFilePath(certToRevoke, crlFilePathRoot);
                _log.WriteEntry("CRL FILE PATH --> " + crlFilePath, EventLogEntryType.Information);

                Utils.RevokeCert(signingCert, message.Certificate, crlFilePath);
                _log.WriteEntry("CERT REVOKED --> " + certToRevoke.SerialNumber, EventLogEntryType.Information);

                if (message.IsDelete)
                {
                    if(certType=="TLS")
                    {
                        certHelper.DeleteTlsCertificate(message.OrgId);
                        _log.WriteEntry("DELETED TLS CERT FROM DB --> " + message.OrgId, EventLogEntryType.Information);
                    }
                    else
                    {
                        certHelper.DeleteEmailCertificate(message.EmailAddress);
                        _log.WriteEntry("DELETED EMAIL CERT FROM DB --> " + message.EmailAddress, EventLogEntryType.Information);
                    }
                }

                queue.DeleteCrlRevokeMsg(message);
                _log.WriteEntry("REMOVED SQS MESSAGE FROM QUEUE --> " + message.CertSerialNumber, EventLogEntryType.Information);

                autoResetEvent.Set();

                return;
            }
            catch (Exception ex)
            {
                _log.WriteEntry(ex.ToString(), EventLogEntryType.Error);
                
                // System.Timers.Timer will silently swallow exception and continue the timer
                return;
            }
        }



    }
}
