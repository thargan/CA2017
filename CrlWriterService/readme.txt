Walkthrough: Creating a Windows Service Application in the Component Designer
https://msdn.microsoft.com/en-us/library/zt39148a%28v=vs.110%29.aspx

To install:
1. run Developer Command Prompt with administrative credentials
2. navigate to project's build output folder; for example... C:\Users\username\git\CA_Service\CrlWriterService\bin\Debug
2. installutil.exe CrlWriterService.exe

To uninstall:
1. run Developer Command Prompt with administrative credentials
2. navigate to project's build output folder; for example... C:\Users\username\git\CA_Service\CrlWriterService\bin\Debug
2. installutil.exe /u CrlWriterService.exe