# Build a project package

$msbuild = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
$packageLocation = "C:\builds\caservice.zip"
$projectdir = 'C:\Program Files (x86)\Jenkins\jobs\CAService_test\workspace\CaService\CaService\'
$project = 'CaService.csproj'

& $msbuild $projectdir$project /target:Package /p:Configuration=Release /P:PackageLocation=$packageLocation
