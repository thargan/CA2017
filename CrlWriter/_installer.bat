@ECHO OFF
 
echo Installing WindowsService...
echo ---------------------------------------------------
C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /i  CrlWriterService.exe

sc start "CrlWriterService"
echo ---------------------------------------------------
echo Done.
pause