using System;
using System.Configuration.Install;
using System.Diagnostics;
using System.ComponentModel;

[RunInstaller(true)]
public class ServiceEventLogInstaller : Installer
{
    private EventLogInstaller myEventLogInstaller;

    public ServiceEventLogInstaller()
    {
        myEventLogInstaller = new EventLogInstaller();
        myEventLogInstaller.Source = "CrlWriter Service";
        myEventLogInstaller.Log = "CrlWriter";
        Installers.Add(myEventLogInstaller);
    }

    public static void Main()
    {
        ServiceEventLogInstaller myInstaller = new ServiceEventLogInstaller();
    }
}