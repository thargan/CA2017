# Building a Jenkins Server

## Provision the EC2 Instance
## Chocolatey
https://chocolatey.org/
## Jenkins Plugins
### Git
### JMeter
+ Edit jmeter.properties:
```
jmeter.save.saveservice.output_format=xml
```
## MS Build
## NuGet
## Set up Git in Jenkins
## Do a build to assert git works
## WebDeploy
http://www.iis.net/downloads/microsoft/web-deploy

## Additional Files Needed for packaging
+ Create the `C:\Program Files (x86)\MSBuild\Microsoft\VisualStudio\v11.0` folder on the jenkins box
+ Extract the contents of `<jenkins_dir>\workspace\CaService\DevOps\build_targets.zip` to the folder you created above
+ Copy the `C:\Program Files (x86)\MSBuild\Microsoft\VisualStudio\v11.0` folder on the jenkins box to `C:\Program Files (x86)\MSBuild\Microsoft\VisualStudio\v12.0`.

## On the Destination Box
### EC2 Security Groups
+ Make sure the following ports are open to the internal network:
    - 80
    - 443
    - 8172
+ Make sure the following ports are open to the external network:
    - 3389 (RDP)

### Set up required services
http://weblogs.asp.net/scottgu/automating-deployment-with-microsoft-web-deploy
+ Web Deployment Tool 2.1
+ IIS: Management Service

http://technet.microsoft.com/en-us/library/ee323462(v=office.13).aspx
+ iisreset /restart
+ IIS: Select Roles Services
    - TODO: Get pictures from #ses channel in slack on 2014-10-28
+ `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -i`
+ Change application pool owner to a user
+ Start Application Pool

# Building and Deploying Packages
Use the PowerShell scripts in this directory as an example of how to build and
deploy .NET applications. Run these scripts in Jenkins to automate the process!
