using CERTENROLLLib;
using Ses.CaService.Core.Models;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Ses.CaService.Core.Crypto
{
    public class DnBuilder
    {
        const string STATE = "MD";
        const string CITY = "Rockville";

        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(DnBuilder));
        
        private CX500DistinguishedName _distinguishedName;

        public CX500DistinguishedName DN
        {
            get
            {
                if (null == _distinguishedName) _distinguishedName = new CX500DistinguishedName();
                return _distinguishedName;
            }
            set
            {
                _distinguishedName = value;
            }
        }

        public static CX500DistinguishedName BuildForReissue(string email, IEmailCert model, X509Certificate2 x509)
        {
            model.Email = email;
            if (String.IsNullOrWhiteSpace(model.City)) { model.City = Utils.ParseDataFromSubject(x509.SubjectName.Name, "L"); }
            if (String.IsNullOrWhiteSpace(model.State)) { model.State = Utils.ParseDataFromSubject(x509.SubjectName.Name, "S"); }
            if (String.IsNullOrWhiteSpace(model.Country)) { model.Country = Utils.ParseDataFromSubject(x509.SubjectName.Name, "C"); }
            
            String cn = null;

            switch (model.AccountType)
            {
                case AccountType.Patient:
                    if (String.IsNullOrWhiteSpace(model.NameFirst) || String.IsNullOrWhiteSpace(model.NameLast))
                        cn = Utils.ParseDataFromSubject(x509.SubjectName.Name, "CN").Replace(" - HISP Managed", String.Empty);
                    else
                        cn = Utils.BuildCommonName(model.NameFirst, model.NameLast);
                    break;

                case AccountType.Professional:
                    if (String.IsNullOrWhiteSpace(model.NameFirst) || String.IsNullOrWhiteSpace(model.NameLast))
                        cn = Utils.ParseDataFromSubject(x509.SubjectName.Name, "CN");
                    else
                        cn = Utils.BuildCommonName(model.NameFirst, model.NameLast, model.NameTitle);
                    break;
            }

            CX500DistinguishedName dn = Build(model, cn);

            if (x509.SubjectName.Name != dn.Name)
            {
                _log.Debug("> Old DN: " + x509.SubjectName.Name);
                _log.Debug("> New DN: " + dn.Name);
            }
            return dn;
        }

        public static CX500DistinguishedName Build(IEmailCert model, String cn)
        {
            CX500DistinguishedName dn = new CX500DistinguishedName();

            switch (model.AccountType)
            {
                case AccountType.Patient:
                    dn = DnBuilder.CreatePatientDn(new DnFields()
                    {
                        CN = cn,
                        E = model.Email,
                        L = model.City ?? CITY,
                        S = model.State ?? STATE,
                        C = model.Country
                    });
                    break;

                case AccountType.Professional:
                    dn = DnBuilder.CreateProfessionalDn(new DnFields()
                    {
                        CN = cn,
                        O = model.OrganizationName,
                        L = model.City ?? CITY,
                        S = model.State ?? STATE,
                        C = model.Country,
                        E = model.Email
                    });
                    break;

                case AccountType.Organization:
                    dn = DnBuilder.CreateOrganizationDn(new DnFields()
                    {
                        O = model.OrganizationName,
                        L = model.City ?? CITY,
                        S = model.State ?? STATE,
                        C = model.Country,
                        E = model.Email
                    });
                    break;
            }

            return dn;
        }


        /// <summary>
        /// Required fields: CN, O, OU, L, S, C
        /// </summary>
        public static CX500DistinguishedName CreateTlsDn(DnFields dnFields)
        {
            dnFields.ValidateRequired("CN,O,OU,L,S,C");
            string subject = BuildSubjectString(AccountType.NULL, dnFields);

            return EncodeDistinguishedName(subject);
        }

        /// <summary>
        /// Required fields: O, L, S, C, E
        /// </summary>
        public static CX500DistinguishedName CreateOrganizationDn(DnFields dnFields)
        {
            dnFields.ValidateRequired("O,L,S,C,E");
            string subject = BuildSubjectString(AccountType.Organization, dnFields);

            return EncodeDistinguishedName(subject);
        }

        /// <summary>
        /// Required fields: CN, O, L, S, C, E
        /// </summary>
        public static CX500DistinguishedName CreateProfessionalDn(DnFields dnFields)
        {
            dnFields.ValidateRequired("CN,O,L,S,C,E");
            string subject = BuildSubjectString(AccountType.Professional, dnFields);

            return EncodeDistinguishedName(subject);
        }

        /// <summary>
        /// Required fields: CN, L, S, C, E
        /// </summary>
        public static CX500DistinguishedName CreatePatientDn(DnFields dnFields)
        {
            dnFields.ValidateRequired("CN,L,S,C,E");
            string subject = BuildSubjectString(AccountType.Patient, dnFields);

            return EncodeDistinguishedName(subject);
        }


         public static string CreateBountyCastleTLSDnString(DnFields dnFields)
        {
             dnFields.ValidateRequired("CN,O,OU,L,S,C");
            string  subjectTemplate = "C={0} ,ST={1}, L={2}, OU={3},  O={4}, CN={5}";
            string    subject = string.Format(subjectTemplate,Clean(dnFields.C),Clean(dnFields.S),Clean(dnFields.L),Clean(dnFields.OU), Clean(dnFields.O),Clean(dnFields.CN));  
            return subject;
        }
        public static string BuildSubjectString(AccountType accountType, DnFields dnFields)
        {
            string subjectTemplate = null;
            string subject = null;

            switch(accountType)
            {
                case AccountType.NULL: // TLS
                    subjectTemplate = "CN={0} - HISP Managed, O={1}, OU={2}, L={3}, S={4}, C={5}";
                    subject = string.Format(subjectTemplate,
                        Clean(dnFields.CN), Clean(dnFields.O), Clean(dnFields.OU), Clean(dnFields.L), Clean(dnFields.S), Clean(dnFields.C));
                    break;

                case AccountType.Organization:
                    subjectTemplate = "O={0} - HISP Managed, L={1}, S={2}, C={3}, E={4}";
                    subject = string.Format(subjectTemplate,
                        Clean(dnFields.O), Clean(dnFields.L), Clean(dnFields.S), Clean(dnFields.C), Clean(dnFields.E));
                    break;

                case AccountType.Professional:
                    subjectTemplate = "CN={0} - HISP Managed, O={1}, L={2}, S={3}, C={4}, E={5}";
                    subject = string.Format(subjectTemplate,
                        Clean(dnFields.CN), Clean(dnFields.O), Clean(dnFields.L), Clean(dnFields.S), Clean(dnFields.C), Clean(dnFields.E));
                    break;

                case AccountType.Patient:
                    subjectTemplate = "CN={0} - HISP Managed, L={1}, S={2}, C={3}, E={4}";
                    subject = string.Format(subjectTemplate, 
                        Clean(dnFields.CN), Clean(dnFields.L), Clean(dnFields.S), Clean(dnFields.C), Clean(dnFields.E));
                    break;
            }
            
            return subject;
        }
        
        private static CX500DistinguishedName EncodeDistinguishedName(String subject)
        {
            // remove multiple space characters
            subject = Regex.Replace(subject, @"[ ]{2,}", @" ");

            var distinguishedName = new CX500DistinguishedName();
            distinguishedName.Encode(subject, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            return distinguishedName;
        }

        private static string Clean(string value)
        {
            // see https://msdn.microsoft.com/en-us/library/aa366101%28v=vs.85%29.aspx

            // remove space or '#' character at the beginning
            // remove space character from end
            string val = value.Trim().TrimStart('#');

            /*
                .Replace(",", string.Empty)
                .Replace("+", string.Empty)
                .Replace("\"", string.Empty)
                .Replace("\\", string.Empty)
                .Replace("<", string.Empty)
                .Replace(">", string.Empty)
                .Replace(";", string.Empty)
                .Replace("=", string.Empty)
                .Replace("/", string.Empty);
            */
            val = Regex.Replace(val, @"[,+""\\<>;=/]", string.Empty);

            return val;
        }
    }
}
