using System;
using System.Threading.Tasks;
using System.Text;
 
namespace Ses.CaService.Core.Crypto
{
    public class DnFields
    {
        public string CN { get; set; }
        public string L { get; set; }
        public string S { get; set; }
        public string C { get; set; }
        public string E { get; set; }
        public string O { get; set; }
        public string OU { get; set; }

        public bool ValidateRequired(string requiredFields)
        {
            bool isValid = false;

            var fields = requiredFields.Split(',');
            foreach (string field in fields)
            {
                var arg = field.Trim();
                var property = this.GetType().GetProperty(arg);
                if (null == property) continue;

                var value = property.GetValue(this, null).ToString();
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("Required property IsNullOrWhiteSpace.", "dnField." + field);
                }
            }
            return isValid;
        }




        public static string getValByAttributeTypeFromIssuerDN(String dn, String attributeType)
        {
            string[] dnSplits = dn.Split (','); 
            foreach (string dnSplit in  dnSplits) 
            {
                string[] cnSplits = dnSplit.Trim().Split('=');
                if (cnSplits[0]==null)
                {
                    return null;
                }
                if (cnSplits[0].ToLower().Equals (attributeType.ToLower())) 
                {
                   
                    if(cnSplits[1]!= null)
                    {
                        return cnSplits[1].Trim();
                    }
                }
            }
            return null;
        }
    }
}
