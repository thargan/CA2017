# Deploy the package we just built

# Define destination boxes
$deploymentBoxes = @(
    @{"destination"="10.0.0.131"; "username"="Administrator"; "password"="(;5drxdrm*i"},
    @{"destination"="107.22.233.119"; "username"="JenkinsUser"; "password"="JeNkInS0@uSeR"}
);

# Deploy to each of the boxes
foreach ($box in $deploymentBoxes.GetEnumerator()) {
   &deploy $box.destination $box.username $box.password
}

function deploy($destination, $username, $password) {
    $webServerName = "https://$($destination):8172/msdeploy.axd,authType=Basic,userName=$username,password='$password'"

    Write-Host "Deploying CaService to $($webServerName)"

    $iisName = "IIS Web Application Name"
    $deploySite = "Default Web Site\caservice"

    $msdeploy = "C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy.exe"
    $contentPath = "C:\builds"

    $msdeployArguments = [string[]]@(
        "-verb:sync",
        "-source:package=$contentPath\caservice.zip",
        "-dest:auto,computerName=$webServerName",
        "-allowUntrusted",
        "-setParam:name='IIS Web Application Name',value='$($deploySite)'")

    Start-Process $msdeploy -ArgumentList $msdeployArguments -NoNewWindow -Wait
}
