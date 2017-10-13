using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Ses.Certman
{
    public class ConsoleCommand
    {
        private List<string> _arguments = new List<string>();
        public IEnumerable<string> Arguments
        {
            get { return _arguments; }
        }
        
        public string Name { get; private set; }
        
        public string LibraryClassName { get; private set; }
        
        public ConsoleCommand(string input, Dictionary<string, Dictionary<string, IEnumerable<ParameterInfo>>> commandLibraries)
        {
            var stringArray = Regex.Split(input, "(?<=^[^\"]*(?:\"[^\"]*\"[^\"]*)*) (?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

            for (int i = 0; i < stringArray.Length; i++)
            {
                if (i == 0)
                {   // first element is the command name
                    this.Name = stringArray[i];                                        
                    foreach(var lib in commandLibraries)
                    {
                        foreach (var methods in lib.Value)
                        {
                            if (methods.Key == this.Name)
                            {
                                this.LibraryClassName = lib.Key;
                                break;
                            }
                        }
                        if (null != this.LibraryClassName) break;
                    }
                    
                    string[] s = stringArray[0].Split('.');
                    if (s.Length == 2)
                    {
                        this.LibraryClassName = s[0];
                        this.Name = s[1];
                    }
                    
                }
                else
                {
                    var inputArgument = stringArray[i];
                    string argument = inputArgument;

                    // Is the argument a quoted text string?
                    var regex = new Regex("\"(.*?)\"", RegexOptions.Singleline);
                    var match = regex.Match(inputArgument);

                    if (match.Captures.Count > 0)
                    {
                        // Get the unquoted text:
                        var captureQuotedText = new Regex("[^\"]*[^\"]");
                        var quoted = captureQuotedText.Match(match.Captures[0].Value);
                        argument = quoted.Captures[0].Value;
                    }
                    _arguments.Add(argument);
                }
            }
        }
    }
}
