# Run JMeter Tests to assert deployment works

$CaServiceIP = "10.0.0.131"
$URLPrefix = "/caservice"

$jobName = "CAService_test"
$jmeter = "C:\jmeter\apache-jmeter-2.11\bin\jmeter.bat"
$jmxFile = "C:\Program Files (x86)\Jenkins\jobs\$jobName\workspace\DevOps\CaServicePostDeployTest.jmx"
$jtlFile = "C:\Program Files (x86)\Jenkins\jobs\$jobName\workspace\caService_results.jtl"

If (Test-Path $jtlFile){
    Remove-Item $jtlFile
}

& $jmeter -n -t $jmxFile -l $jtlFile -JCaServiceIP="$CaServiceIP" -JURLPrefix="$URLPrefix"
