using Amazon.SQS;
using Amazon.SQS.Model;
using Newtonsoft.Json;
using Ses.CaService.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Ses.CaService.Core.Queuing
{
    public class SqsHelper
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(SqsHelper));

        private string _receiptHandle;

        private AmazonSQSConfig _sqsConfig;
        public AmazonSQSConfig SqsConfig 
        {
            get
            {
                if (null == _sqsConfig)
                {
                    _sqsConfig = new AmazonSQSConfig();
                }
                return _sqsConfig;
            }

            private set 
            {
                if (null == _sqsConfig)
                {
                    _sqsConfig = new AmazonSQSConfig();
                }
                _sqsConfig = value;
            }
        }

        private AmazonSQSClient _sqsClient;
        public AmazonSQSClient SqsClient
        {
            get
            {
                if (null == _sqsClient)
                {
                    _sqsClient = new AmazonSQSClient(SqsConfig);
                }
                return _sqsClient;
            }

            private set
            {
                if (null == _sqsClient)
                {
                    _sqsClient = new AmazonSQSClient(SqsConfig);
                }
                _sqsClient = value;
            }
        }

        public SqsHelper() {
            SqsConfig.ServiceURL = "https://sqs.us-east-1.amazonaws.com";
        }

        public void EnqueueCrlRevokeMsg(CrlRevokeMessage message)
        {
            string messageAsJson = JsonConvert.SerializeObject(message);
            var request = new SendMessageRequest()
            {
                QueueUrl = Config.AwsCrlRevokeSqsUrl,
                MessageBody = messageAsJson
            };
            SendMessageResponse sendMessageResponse = SqsClient.SendMessage(request);

            if (System.Net.HttpStatusCode.OK.GetType() == sendMessageResponse.HttpStatusCode.GetType())
            {
                _log.Debug("> SQS CRL Revoke Message enqueued for Serial Number: " + message.CertSerialNumber);
            }
        }

        public CrlRevokeMessage DequeueCrlRevokeMsg()
        {
            ReceiveMessageRequest request = new ReceiveMessageRequest();
            request.QueueUrl = Config.AwsCrlRevokeSqsUrl;
            ReceiveMessageResponse receiveMessageResponse = SqsClient.ReceiveMessage(request);

            if (receiveMessageResponse.Messages.Count > 0 && null != receiveMessageResponse.Messages[0].ReceiptHandle)
            {
                _receiptHandle = receiveMessageResponse.Messages[0].ReceiptHandle;
            }

            CrlRevokeMessage message = null;
            if (receiveMessageResponse.Messages.Count > 0 && null != receiveMessageResponse.Messages[0].Body)
            {
                message = JsonConvert.DeserializeObject<CrlRevokeMessage>(receiveMessageResponse.Messages[0].Body);
                _log.Debug("> SQS CRL Revoke Message dequeued for Serial Number: " + message.CertSerialNumber);
            }

            return message;
        }

        public void DeleteCrlRevokeMsg(CrlRevokeMessage message)
        {
            DeleteMessageRequest request = new DeleteMessageRequest();
            request.QueueUrl = Config.AwsCrlRevokeSqsUrl;
            
            if (null == _receiptHandle)
            {
                throw new ApplicationException("ReceiptHandle is null");
            }
            request.ReceiptHandle = _receiptHandle;
            var response = SqsClient.DeleteMessage(request);

            _log.Debug("> SQS CRL Revoke Message deleted for Serial Number: " + message.CertSerialNumber);
        }
    }
}