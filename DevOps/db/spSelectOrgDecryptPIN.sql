USE [certDB]
GO

/****** Object:  StoredProcedure [dbo].[spSelectOrgDecryptPIN]    Script Date: 4/20/2015 4:07:06 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[spSelectOrgDecryptPIN]
	(
	    @OrgId nvarchar(150)
	)
AS
BEGIN

	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
	SELECT CONVERT(varchar, DecryptByKey([EncryptedPIN])) AS 'Decrypted PIN'
	FROM [dbo].[TLSCertificate]
	WHERE [OrgId] = @OrgId

END

GO


