
Set-AWSCredentials -StoredCredentials SESCAService

Set-DefaultAWSRegion us-east-1

$ErrorOutputFile= "C:\dev\certman\ErrorLog.txt"
$certMan = "c:\dev\certman\certman.exe"
$arg1 = "rt" # renewToday
$currentTime =Get-Date
$subject = "Certificate renew process ran at  " + $currentTime 

Try
{
write-host "running " $certMan $arg1
& $certMan $arg1 

# check for errors in the last log file

$dir = "C:\dev\certman\logs"
$latest = Get-ChildItem -Path $dir | Sort-Object LastAccessTime -Descending | Select-Object -First 1
#$latest.name

$noCerts = 0

# check to see if no certs needed to be renewed
$result = select-string -Path $latest -Pattern "no expiring certs"

if ($result.Count -eq 1) 
{
    # done     
    $message = "No certs needed to be renewed"
    $noCerts = 1
    # end
}
else
{ 
     $numFailed = select-string -Path $latest -pattern "Failed to renew"
     $numRenewed = select-string -Path $latest -pattern "Renewed :"
     $numCacheInvalidationFailed = select-string -Path $latest -pattern "Cache Invalidation Failed :" 
     $message = $numRenewed.Count.ToString() + " certificates successfully  renewed |  "  + $numFailed.Count.ToString() +" certificates   failed to renew |"+ $numCacheInvalidationFailed.Count.ToString()+ " cache invalidation  failed    "       
   
  if ($numRenewed -and  $numRenewed.Count -gt 0){
 $arg2="flushcache"
 & $certMan $arg2
    $cacheFlushFailed = select-string -Path $latest -pattern "Cache Flush Failed :" 
    if ($cacheFlushFailed){
          $message = $numRenewed.Count.ToString() + " certificates successfully  renewed |   "  + $numFailed.Count.ToString() +" certificates   failed to renew | "+ $numCacheInvalidationFailed.Count.ToString()+ " cache invalidation  failed  | cache flushed failed" 
    }else{
         
            $cacheFlushSuccessful = select-string -Path $latest -pattern "Cache Flushed Successfully :" 
           if ($cacheFlushSuccessful){
              $message = $numRenewed.Count.ToString() + " certificates successfully  renewed |   "  + $numFailed.Count.ToString() +" certificates   failed to renew | "+ $numCacheInvalidationFailed.Count.ToString()+ " cache invalidation  failed  | cache flush Successfull " 
            }
        
     }
   }
} 
 Write-Host $message 
   Publish-SNSMessage -TopicArn arn:aws:sns:us-east-1:293484591747:CA-Renewal  -Subject $subject -Message $message

}
Catch
{
   
     $ErrorMessage = $_.Exception.Message 
     $ErrorMessage >>$ErrorOutputFile;
   
}

Try
{
#--Now do the crl files update .The crls files will be read from the directory  ="crlFilePath" value="\\10.20.1.6\crl2\" \\This is the direct address.net machine and the dir mapped is  c:\dev\crls
$subject="Crl files update"
$currentTime =Get-Date
$message="Starting crl files update at"+ $currentTime
Write-Host $message
 
$arg3="updatecrls"
& $certMan $arg3
$currentTime =Get-Date
$message="completed  crl files update at "+ $currentTime  
Write-Host $message 

  Publish-SNSMessage -TopicArn arn:aws:sns:us-east-1:293484591747:CA-Renewal  -Subject $subject -Message $message


}

Catch
{
   
     $ErrorMessage = $_.Exception.Message 
     $ErrorMessage >>$ErrorOutputFile;
   
}

# get instance id and shut down
$instanceID = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/instance-id

# sleep for a couple minutes to allow for CRL Revocation Windows Service to finish
Start-Sleep 2 

Stop-EC2Instance $instanceID