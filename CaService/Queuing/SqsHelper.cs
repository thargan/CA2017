using Amazon.SQS;
using Amazon.SQS.Model;
using Newtonsoft.Json;
using Ses.CaService.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Ses.CaService.Queuing
{
    public class SqsHelper
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(SqsHelper));

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

        public void EnqueueCrlRevokeMsg(CrlRevokeMessage msg )
        {
            string msgJson = JsonConvert.SerializeObject(msg);
            var request = new SendMessageRequest()
            {
                QueueUrl = Config.AwsCrlRevokeSqsUrl,
                MessageBody = msgJson
            };
            SendMessageResponse sendMessageResponse = SqsClient.SendMessage(request);

            if (System.Net.HttpStatusCode.OK.GetType() == sendMessageResponse.HttpStatusCode.GetType())
            {
                log.Debug("SQS CRL Revoke Message enqueued: " + sendMessageResponse.HttpStatusCode);
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
            }

            log.Debug("SQS CRL Revoke Message dequeued --> ReceiptHandle: " + _receiptHandle);

            return message;
        }

        public void DeleteCrlRevokeMsg()
        {
            DeleteMessageRequest request = new DeleteMessageRequest();
            request.QueueUrl = Config.AwsCrlRevokeSqsUrl;
            
            if (null == _receiptHandle)
            {
                throw new ApplicationException("ReceiptHandle is null");
            }
            request.ReceiptHandle = _receiptHandle;
            var response = SqsClient.DeleteMessage(request);

            log.Debug("SQS CRL Revoke Message deleted: " + response.HttpStatusCode);
        }
    }
}