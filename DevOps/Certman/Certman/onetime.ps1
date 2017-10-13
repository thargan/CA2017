
Set-AWSCredentials -StoredCredentials SESCAService

Set-DefaultAWSRegion us-east-1

 
$certMan = "c:\dev\certman\certman.exe"
#$arg1 = "r rmcdirect@direct.summit-healthcare.org 06/03/2016" 
$outputFile= "C:\renew\youcare-Aug17\current\processing.times"
$certsAddressFile="C:\renew\youcare-Aug17\current\renew.txt"
$certsToReissue = get-content $certsAddressFile
$comment="Starting to process file " +$certsAddressFile

$comment>>$outputFile
$a =Get-Date
$currentTime="Started at "+ $a 
$currentTime>>$outputFile
Write-Host $currentTime
foreach ($cert in $certsToReissue){
$arg1 = $cert
#Write-Host $arg1
  & $certMan $arg1

  
}
$a = Get-Date
$currentTime="Ended at "+ $a  
$currentTime>>$outputFile
Write-Host $currentTime