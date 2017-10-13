# CA_Service
The CA Service is responsible for the creation, dissemination,
and revocation of certificates.

## Available Endpoints
Microsoft's ASP .NET Web API is self-documenting. As a result, endpoints 
(and the arguments they accept) can be viewed by visiting /CaService/Help endpoint.

## Creating Certificates
There are currently two types of profiles that the CA Service is responsible
for creating:

+ Email Certificates
+ TLS Certificates

## Testing the Endpoint
For an extensive list of GET, POST, PUT, and DELETE calls, please refer to the
[Apache JMeter](http://jmeter.apache.org/) script `CaServicePostDeployTest.jmx`
in the DevOps folder. The PUT examples, especially, demonstrate calling the
service with JSON payloads.

Installing Apache JMeter and loading the file will enable you to invoke many
tests sequentially and assert that the endpoint behaves as expected. You may
have to change the IP address of the server you are testing, which can be
accomplished by editing the fields in the `CaService Instance Variables` User-
Defined variables section of the JMeter Script.

## Installing the CA Service
The CA Service can be automatically deployed to any server running Web Deploy
3.5 or greater via the `msdeploy` command. This is handled automatically by
the SES [Jenkins server](http://54.86.8.188:8080/) in the `CaService` job.

The CA Service Jenkins job builds and deploys the application through a series
of PowerShell scripts. 

## Automatic Deployment
After setting up webhooks in Jenkins, the project should be automatically built
every time new code is pushed to Github. See [this link](http://thepracticalsysadmin.com/setting-up-a-github-webhook-in-jenkins/)
for more details.
