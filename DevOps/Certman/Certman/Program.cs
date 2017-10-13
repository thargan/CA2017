using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.IO;
using System.Configuration;
using Ses.CaService.Core.Crypto;

namespace Ses.Certman
{
    //This is the helper class for creating the certs from a file input
    public class CreateRecord
    {
        public string DirectEmailAddress { get; set; }
        public string AccountType { get; set; }
        public string ProfileName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Title { get; set; }
        public string OrganzationName { get; set; }

    }

    class Program
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(Program));
        const string _commandNamespace = "Ses.Certman.Commands";
        static Dictionary<string, Dictionary<string, IEnumerable<ParameterInfo>>> _commandLibraries;

        static void Main(string[] args)
        {
            Console.Title = typeof(Program).Name;

            Directory.CreateDirectory("logs");

            _commandLibraries = new Dictionary<string, Dictionary<string, IEnumerable<ParameterInfo>>>();

            // Use reflection to load each class in the Commands namespace:
            var q = from t in Assembly.GetExecutingAssembly().GetTypes()
                    where t.IsClass && t.Namespace == _commandNamespace
                    select t;

            var commandClasses = q.ToList();

            foreach (var commandClass in commandClasses)
            {
                var methods = commandClass.GetMethods(BindingFlags.Static | BindingFlags.Public);
                var methodDictionary = new Dictionary<string, IEnumerable<ParameterInfo>>();
                foreach (var method in methods)
                {
                    string commandName = method.Name;
                    methodDictionary.Add(commandName, method.GetParameters());
                }

                _commandLibraries.Add(commandClass.Name, methodDictionary);
            }

            if(args.Length > 0)
                Run(args[0]);
            else
                Run();
        }

        static void Run(string command=null)
        {
            bool _exit = false;
            while (!_exit)
            {
                string consoleInput;

                if (command != null) consoleInput = command;
              
                else consoleInput = ReadFromConsole();
                
                if (string.IsNullOrWhiteSpace(consoleInput)) continue;

                if (consoleInput.ToLower() == "quit" || consoleInput.ToLower() == "q")
                {
                    _exit = true;
                    continue;
                }

                if (consoleInput.ToLower().Contains("createcerts"))
                {

                    createFromFile(consoleInput);
                    _exit = true;

                }
                if (consoleInput.ToLower().Contains("updatecrls"))
                {

                    UpdateCrls();
                    _exit = true;

                } 
                if (consoleInput.ToLower().Contains("flushcache"))
                {

                    FlushCache();
                    _exit = true;

                }
                else
                {

                    try
                    {
                        var cmd = new ConsoleCommand(consoleInput, _commandLibraries);
                        StringBuilder result = Execute(cmd);
                        if (cmd.Name.Length <= 2) // all abbreviated commands Environment.Exit(0) from console app
                        {
                            WriteToConsole(result, true);
                        }
                        else
                        {
                            WriteToConsole(result);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteToConsole(String.Format("{0}{1} --> {2}{0}", Environment.NewLine, consoleInput, ex.Message), false);
                    }
                }
            }
        }

        static StringBuilder Execute(ConsoleCommand command)
        {
            StringBuilder badCommandMessage = new StringBuilder(string.Format("Unrecognized command: {0}", command.Name));

            if (!_commandLibraries.ContainsKey(command.LibraryClassName))
            {
                return badCommandMessage;
            }

            var methodDictionary = _commandLibraries[command.LibraryClassName];
            if (!methodDictionary.ContainsKey(command.Name))
            {
                return badCommandMessage;
            }

            var methodParameterValueList = buildMethodParameterValueList(command, methodDictionary);

            // Set up to invoke method via reflection:
            Assembly current = typeof(Program).Assembly;

            // Need full Namespace
            Type commandLibaryClass = current.GetType(_commandNamespace + "." + command.LibraryClassName);

            object[] inputArgs = null;
            if (methodParameterValueList.Count > 0)
            {
                inputArgs = methodParameterValueList.ToArray();
            }
            var typeInfo = commandLibaryClass;

            // This will throw if the number of arguments provided does not match the number 
            // required by the method signature, even if some are optional:
            try
            {
                var result = typeInfo.InvokeMember(
                    command.Name,
                    BindingFlags.InvokeMethod | BindingFlags.Static | BindingFlags.Public,
                    null, null, inputArgs);
                return new StringBuilder(result.ToString());
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException;
            }
        }

        // Ensure the correct number of required arguments were provided
        private static List<object> buildMethodParameterValueList(ConsoleCommand command, Dictionary<string, IEnumerable<ParameterInfo>> methodDictionary)
        {
            var methodParameterValueList = new List<object>();
            IEnumerable<ParameterInfo> paramInfoList = methodDictionary[command.Name].ToList();

            // Validate # of required arguments provided... some may be optional
            var requiredParams = paramInfoList.Where(p => p.IsOptional == false);
            var optionalParams = paramInfoList.Where(p => p.IsOptional == true);
            int requiredCount = requiredParams.Count();
            int optionalCount = optionalParams.Count();
            int providedCount = command.Arguments.Count();

            if (requiredCount > providedCount)
            {
                throw new ArgumentException(string.Format("Missing required argument. {0} required, {1} optional, {2} provided", requiredCount, optionalCount, providedCount));
            }

            // Make sure all arguments are coerced to the proper type, and that there is a 
            // value for every emthod parameter. The InvokeMember method fails if the number 
            // of arguments provided does not match the number of parameters in the 
            // method signature, even if some are optional.
            if (paramInfoList.Count() > 0)
            {
                foreach (var param in paramInfoList)
                {
                    methodParameterValueList.Add(param.DefaultValue);
                }

                for (int i = 0; i < command.Arguments.Count(); i++)
                {
                    var methodParam = paramInfoList.ElementAt(i);
                    var typeRequired = methodParam.ParameterType;
                    object value = null;
                    try
                    {
                        // From the console, all arguments are strings... coerce to match method paramter
                        value = ArgumentsHelper.CoerceArgument(typeRequired, command.Arguments.ElementAt(i));
                        methodParameterValueList.RemoveAt(i);
                        methodParameterValueList.Insert(i, value);
                    }
                    catch (ArgumentException)
                    {
                        string argumentName = methodParam.Name;
                        string argumentTypeName = typeRequired.Name;
                        string message = string.Format("The value passed for argument '{0}' cannot be cast to type '{1}'", argumentName, argumentTypeName);
                        throw new ArgumentException(message);
                    }
                }
            }
            return methodParameterValueList;
        }

        public static void WriteToConsole(StringBuilder message, bool exit=false)
        {
            WriteToConsole(message.ToString(), exit);
        }

        public static void WriteToConsole(string message, bool exit)
        {
            if(message.Length > 0)
            {
                Log.WriteToLog(message);
                Console.WriteLine("  " + message);
                
                if(exit) Environment.Exit(0);
            }
        }
        
        const string _readPrompt = "> certman$ ";
        public static string ReadFromConsole(string promptMessage = "")
        {
            Console.Write(_readPrompt + promptMessage);
            return Console.ReadLine();
        }


        //Added so a patient data can be  loaded in a csv file
        //The command to be given is createcerts filename 
        public static void createFromFile(string consoleInput)
        {

            var consoleValues = consoleInput.Split(' ');
            string fileName = consoleValues[1];

            List<CreateRecord> records = new List<CreateRecord>();

            using (var reader = new StreamReader(File.OpenRead(fileName)))
            {
              
              
                while (!reader.EndOfStream)
                {
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    CreateRecord newRecord = new CreateRecord
                    {
                        DirectEmailAddress = values[0],
                        AccountType = values[1],
                        ProfileName = values[2],
                        FirstName = values[3],
                        LastName = values[4],
                        City = values[5],
                        State = values[6],
                        Title = values[7],
                        OrganzationName = values[8]
                    };
                    records.Add(newRecord);
                }

                foreach (var rec in records)
                {

                    string directEmailAddress = rec.DirectEmailAddress;
                    string accountType = rec.AccountType;
                    string profileName = rec.ProfileName;
                    string firstName = rec.FirstName;
                    string lastName = rec.LastName;
                    string city = rec.City;
                    string state = rec.State;
                    string title = rec.Title;
                    string OrganzationName = rec.OrganzationName;

                    StringBuilder str = Ses.Certman.Commands.CreateCommand.c(directEmailAddress, accountType, profileName, firstName, lastName, city, state, title, OrganzationName);
                     WriteToConsole(str,false);

                }

            }


        }

        public static void UpdateCrls()
        {

            try
            {
                var crlFilePathRoot = ConfigurationManager.AppSettings["crlFilePath"];

                _log.InfoFormat("Checking for crl files in the path {0}", crlFilePathRoot);
                string[] crlFiles = System.IO.Directory.GetFiles(crlFilePathRoot, "*.crl");

                foreach (string file in crlFiles)
                {
                    _log.InfoFormat("found  crl file {0}  in the path {1}", file,crlFilePathRoot);
                    Utils.UpdateCrlDate(file);
                }
            }
            catch (Exception e)
            {
           
                _log.Error(String.Format("Encountered error while trying to get the names of crl files"), e); 

            }



        }


        public static void FlushCache()
        { 
            try
            {
             
                StringBuilder str = Ses.Certman.Commands.DefaultCommands.FlushCache(); 
                WriteToConsole(str,true);
            }
            catch (Exception e)
            {
           
                _log.Error(String.Format("Encountered error while trying to flush the cache"), e); 

            } 


        }
         

    }

  
}
