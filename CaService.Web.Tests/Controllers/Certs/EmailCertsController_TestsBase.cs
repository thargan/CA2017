using System;
using System.Linq;
using System.Collections.Generic;
using System.Web.Http;
using System.Web.Http.Routing;
using System.Net.Http;
using System.Diagnostics;
using System.Web.Http.Results;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ses.CaService.Controllers;
using Ses.CaService.Core.Models;
using Ses.CaService.Core;
using Ses.CaService.Core.Crypto;
using Ses.CaService.Data;

namespace CaService.Web.Tests
{
    [TestClass]
    public class EmailCertsController_TestsBase
    {
        private CaServiceDbContext _db;
        protected CaServiceDbContext db
        {
            get
            {
                if (_db == null)
                {
                    _db = new CaServiceDbContext();
                }
                return _db;
            }
        }

        private Dictionary<AccountType, string> _mapAccountTypeToProfileName = new Dictionary<AccountType, string>
        {
            { AccountType.Patient, "TEST Patient" },
            { AccountType.Professional, "TEST Provider/DirectTrust" },
            { AccountType.Organization, "TEST Provider/Non-DirectTrust"}

        };

        private Certificate _certificate;
        protected Certificate Certificate
        {
            get { return _certificate; }
        }
        protected Certificate LoadTestCertificate(AccountType type)
        {
            var profileName = _mapAccountTypeToProfileName.Where(x => x.Key == type).FirstOrDefault().Value;
            _certificate = db.Certificates.Where(e => e.CreatedBy == TestData.BY && e.ProfileName == profileName).FirstOrDefault();
            if (null == _certificate)
            {
                TestData.SetupDatabase();
                _certificate = db.Certificates.Where(e => e.CreatedBy == TestData.BY && e.ProfileName == profileName).FirstOrDefault();
            }
            return _certificate;
        }

        protected Certificate RetrieveCertificateFromDB(string emailAddress)
        {
            using (var freshDbContext = new CaServiceDbContext())
            {
                return freshDbContext.Certificates.Where(e => e.EmailAS1 == emailAddress).FirstOrDefault();
            }
        }

        protected EmailCertsController _controller;
        protected EmailCertsController Controller
        {
            get
            {
                if (null == _controller)
                {
                    _controller = new EmailCertsController();
                    _controller.Configuration = new HttpConfiguration();
                }
                return _controller;
            }
            set { _controller = value; }
        }

        protected TestUtils<EmailCertsController, EmailCreateCertRequest> Utils_POST = new TestUtils<EmailCertsController, EmailCreateCertRequest>();
        protected EmailCreateCertRequest PatientModel_POST = TestData.Models.ValidPatientModel_POST;
        protected EmailCreateCertRequest ProfessionalModel_POST = TestData.Models.ValidProfessionalModel_POST;

        protected TestUtils<EmailCertsController, EmailUpdateCertRequest> Utils_PUT = new TestUtils<EmailCertsController, EmailUpdateCertRequest>();
        protected EmailUpdateCertRequest PatientModel_PUT = TestData.Models.ValidPatientModel_PUT;
        protected EmailUpdateCertRequest ProfessionalModel_PUT = TestData.Models.ValidProfessionalModel_PUT;

        protected TestUtils Utils_DELETE = new TestUtils();

        protected HttpRouteData GetRouteData(string routeTemplate)
        {
                _controller.Configuration.Routes.Clear();
                var route = _controller.Configuration.Routes.MapHttpRoute("TestRoute", routeTemplate);
                return new HttpRouteData(route, new HttpRouteValueDictionary { { "email", ProfessionalModel_POST.Email } });
        }

        protected string GetTestSubject(AccountType type, ICaServiceModel model)
        {
            switch (type)
            {
                case AccountType.Patient:
                    return DnBuilder.BuildSubjectString(AccountType.Patient, new DnFields()
                    {
                        CN = model.NameFirst + " " + model.NameLast,
                        E = model.Email,
                        L = model.City,
                        S = model.State,
                        C = model.Country
                    });

                case AccountType.Professional:
                    return DnBuilder.BuildSubjectString(AccountType.Professional, new DnFields()
                    {
                        CN = model.NameFirst + " " + model.NameLast,
                        E = model.Email,
                        L = model.City,
                        S = model.State,
                        C = model.Country,
                        O = model.OrganizationName
                    });
            }

            return null;
        }

        [TestCleanup]
        public void CleanupTestData()
        {
            TestData.Models.ResetAllModels();
        }
        
        /*
         * {
            "EmailAddress": "fincher-test-1987@test.com",
            "KeyPairs": [
                {
                    "Type": "Encryption",
                    "SerialNumber": "1E385F90667E8AA24177FFA8817E86A7",
                    "Thumbprint": "46915FC2E84C5912EDD80BE3CCAF50526091635C"
                },
                {
                    "Type": "Signing",
                    "SerialNumber": "531C99DACD3FF19841F03FDEF3B99BFF",
                    "Thumbprint": "382799F7C61716D6942E4489B7C0A479B8DBB1D9"
                }
            ],
            "Href": "http://localhost/caservice/api/v2/certs/email/fincher-test-1987@test.com",
            "CertProfileName": "badCrl",
            "EffectiveDate": "6/15/2015 2:19:42 PM",
            "ExpirationDate": "6/15/2016 6:19:41 PM",
            "Subject": "CN=First Last - HISP Managed, L=Rockville, S=Maryland, C=US, E=fincher-test-1987@test.com",
            "CrlUrl": "http://directaddress.net/crl",
            "AiaPath": "http://www.directaddress.net/public/badCrl.cer",
            "Issuer": {
                "Subject": "CN=SES Direct Patient Community Intermediate CA, O=Secure Exchange Solutions, OU=SES Directory Services, L=Rockville, S=Maryland, C=US",
                "SerialNumber": "245C36DCAD3AFDBB46EA9B1C491B99EC"
            }
        }
        */
    }
}
