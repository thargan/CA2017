 
Set-AWSCredentials -StoredCredentials SESCAService

Set-DefaultAWSRegion us-east-1 
$certMan = "c:\dev\certman\certman.exe" 
 
#Publish-SNSMessage -TopicArn arn:aws:sns:us-east-1:293484591747:CA-Renewal  -Subject $subject -Message $message

#--Now do the crl files update .The crls files will be read from the directory  ="crlFilePath" value="\\10.20.1.6\crl2\" \\This is the direct address.net machine and the dir mapped is  c:\dev\crls
$subject="Crl files update"
$currentTime =Get-Date
$message="Starting crl files update at"+ $currentTime
Write-Host $message
 
$arg2="updatecrls"
& $certMan $arg2
$currentTime =Get-Date
$message="completed  crl files update at "+ $currentTime  
Write-Host $message 
 