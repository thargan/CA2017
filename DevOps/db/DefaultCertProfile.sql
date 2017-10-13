/*******************************
  Default Certificate Profiles
*******************************/
GO
INSERT INTO [dbo].[CertificateProfile] (
                ProfileName, SigningCertSerialNumber, CRLURL, AIAPath,
                CertPolicyOID, LOAPolicyOID, CategoryOID, EnhancedKeyUsageOID )
VALUES
('Provider/DirectTrust','0d3c1d44a4548b9049df657f6f42fbc2','http://directaddress.net/crl/directaddress.crl','http://www.directaddress.net/public/intermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.3','1.3.6.1.4.1.41179.2.1','1.3.6.1.5.5.7.3.4'),
('Provider/Non-DirectTrustIdP','4f27a27695cacc8a4dda1f9183f0b62e','http://directaddress.net/crl/directmessaging.crl','http://www.directaddress.net/public/MessagingIntermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.3','1.3.6.1.4.1.41179.2.1','1.3.6.1.5.5.7.3.4'),
('PatientIdP','31569c236045d085460207d6851fbe3e','http://directaddress.net/crl/directpatient.crl','http://www.directaddress.net/public/PatientIntermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.3','1.3.6.1.4.1.41179.2.4','1.3.6.1.5.5.7.3.4'),
('TLS','4f27a27695cacc8a4dda1f9183f0b62e','http://directaddress.net/crl/directaddress.crl','http://www.directaddress.net/public/MessagingIntermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.3','1.3.6.1.4.1.41179.2.2','1.3.6.1.5.5.7.3.1; 1.3.6.1.5.5.7.3.2'),
('Provider/Non-DirectTrust','4f27a27695cacc8a4dda1f9183f0b62e','http://directaddress.net/crl/directmessaging.crl','http://www.directaddress.net/public/MessagingIntermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.1','1.3.6.1.4.1.41179.2.1','1.3.6.1.5.5.7.3.4'),
('Patient','31569c236045d085460207d6851fbe3e','http://directaddress.net/crl/directpatient.crl','http://www.directaddress.net/public/PatientIntermediateCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.1','1.3.6.1.4.1.41179.2.4','1.3.6.1.5.5.7.3.4'),
('Patient/DirectTrust','55e90e75cb9d07804f7c73b18670d94a','http://directaddress.net/crl/PatientCommunity.crl','http://www.directaddress.net/public/PatientCommunityCA.der','1.3.6.1.4.1.41179.0.1.2','1.3.6.1.4.1.41179.1.3','1.3.6.1.4.1.41179.2.4','1.3.6.1.5.5.7.3.4')
