GO
CREATE TABLE [dbo].[CertificateProfile] (
    [Id]                        INT             IDENTITY(1,1) NOT NULL,
    [ProfileName]               VARCHAR (150)   NULL,
    [SigningCertSerialNumber]   VARCHAR (150)   NULL,
    [CRLURL]                    VARCHAR (150)   NULL,
    [AIAPath]                   VARCHAR (150)   NULL,
    [CertPolicyOID]             VARCHAR (150)   NULL,
    [LOAPolicyOID]              VARCHAR (150)   NULL,
    [CategoryOID]               VARCHAR (150)   NULL,
    [EnhancedKeyUsageOID]       VARCHAR (300)   NULL,
    [DateCreated]               DATETIME2 (7)   NULL    DEFAULT GETDATE(),
    [CreatedBy]                 NVARCHAR (50)   NULL,
    [DateModified]              DATETIME2 (7)   NULL    DEFAULT GETDATE(),
    [ModifiedBy]                NVARCHAR (50)   NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);
CREATE NONCLUSTERED INDEX certPro_pName ON [dbo].[CertificateProfile] ([ProfileName]);

/*******************************
  Default Certificate Profiles
*******************************/
GO
INSERT INTO [dbo].[CertificateProfile] (
                ProfileName, SigningCertSerialNumber, CRLURL, AIAPath,
                CertPolicyOID, LOAPolicyOID, CategoryOID, EnhancedKeyUsageOID )
VALUES
    (
        'Provider/DirectTrust',
        '0d3c1d44a4548b9049df657f6f42fbc2',
        'http://directaddress.net/crl/directaddress.crl',
        'http://www.directaddress.net/public/intermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.3',
        '1.3.6.1.4.1.41179.2.1',
        '1.3.6.1.5.5.7.3.4'
    ),
    
    (
        'Provider/Non-DirectTrustIdP',
        '4f27a27695cacc8a4dda1f9183f0b62e',
        'http://directaddress.net/crl/directmessaging.crl',
        'http://www.directaddress.net/public/MessagingIntermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.3',
        '1.3.6.1.4.1.41179.2.1',
        '1.3.6.1.5.5.7.3.4'
    ),
    
    
    (
        'PatientIdP',
        '31569c236045d085460207d6851fbe3e',
        'http://directaddress.net/crl/directpatient.crl',
        'http://www.directaddress.net/public/PatientIntermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.3',
        '1.3.6.1.4.1.41179.2.4',
        '1.3.6.1.5.5.7.3.4'
    ),
    
    
    (
        'TLS',
        '4f27a27695cacc8a4dda1f9183f0b62e',
        'http://directaddress.net/crl/directaddress.crl',
        'http://www.directaddress.net/public/MessagingIntermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.3',
        '1.3.6.1.4.1.41179.2.2',
        '1.3.6.1.5.5.7.3.1; 1.3.6.1.5.5.7.3.2'
    ),
    
    
    (
        'Provider/Non-DirectTrust',
        '4f27a27695cacc8a4dda1f9183f0b62e',
        'http://directaddress.net/crl/directmessaging.crl',
        'http://www.directaddress.net/public/MessagingIntermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.1',
        '1.3.6.1.4.1.41179.2.1',
        '1.3.6.1.5.5.7.3.4'
    ),
    (
        'Patient',
        '31569c236045d085460207d6851fbe3e',
        'http://directaddress.net/crl/directpatient.crl',
        'http://www.directaddress.net/public/PatientIntermediateCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.1',
        '1.3.6.1.4.1.41179.2.4',
        '1.3.6.1.5.5.7.3.4'
    ),
    (
        'Patient/DirectTrust',
        '55e90e75cb9d07804f7c73b18670d94a',
        'http://directaddress.net/crl/PatientCommunity.crl',
        'http://www.directaddress.net/public/PatientCommunityCA.cer',
        '1.3.6.1.4.1.41179.0.1.2',
        '1.3.6.1.4.1.41179.1.3',
        '1.3.6.1.4.1.41179.2.4',
        '1.3.6.1.5.5.7.3.4'
    )
/***************************************
  TEST Certificate Profiles TEST UPDATES
  Uncomment these to replace the valid issuing cert serials with test values
***************************************/
/*
GO
UPDATE [dbo].[CertificateProfile] SET SigningCertSerialNumber = '533E17B88FEB479B415DE47184B7F056';
*/

/***************************************
  TEST Certificate Profiles TEST INSERTS
  Uncomment these to insert additional test values with test issuing cert serials
***************************************/
/*
GO
INSERT INTO [dbo].[CertificateProfile] (
                ProfileName, SigningCertSerialNumber, CRLURL, AIAPath,
                CertPolicyOID, LOAPolicyOID, CategoryOID, EnhancedKeyUsageOID )
       VALUES
          ( 'TEST Provider/DirectTrust',
            '533E17B88FEB479B415DE47184B7F056',
            'http://directaddress.net/crl/secureexsolutions.crl',
            'http://www.directaddress.net/public/intermediateCA.der',
            '1.3.6.1.4.1.41179.0.1',
            '1.3.6.1.4.1.41179.1.3',
            '1.3.6.1.4.1.41179.2.1',
            '1.3.6.1.5.5.7.3.4'
          ),

          ( 'TEST Provider/Non-DirectTrust',
            '533E17B88FEB479B415DE47184B7F056',
            'http://directaddress.net/crl/secureexsolutions.crl',
            'http://www.directaddress.net/public/MessagingIntermediateCA.der',
            '1.3.6.1.4.1.41179.0.1',
            '1.3.6.1.4.1.41179.1.3',
            '1.3.6.1.4.1.41179.2.1',
            '1.3.6.1.5.5.7.3.4'
          ),

          ( 'TEST Patient',
            '533E17B88FEB479B415DE47184B7F056',
            'http://directaddress.net/crl/secureexsolutions.crl',
            'http://www.directaddress.net/public/PatientIntermediateCA.der',
            '1.3.6.1.4.1.41179.0.1',
            '1.3.6.1.4.1.41179.1.3',
            '1.3.6.1.4.1.41179.2.4',
            '1.3.6.1.5.5.7.3.4'
          ),

          ( 'TEST TLS',
            '533E17B88FEB479B415DE47184B7F056',
            'http://directaddress.net/crl/secureexsolutions.crl',
            'http://www.directaddress.net/public/intermediateCA.der',
            '1.3.6.1.4.1.41179.0.1',
            '1.3.6.1.4.1.41179.1.3',
            '1.3.6.1.4.1.41179.2.1',
            '1.3.6.1.5.5.7.3.2'
          );
*/
