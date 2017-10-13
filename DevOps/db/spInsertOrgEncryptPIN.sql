USE [certDB]
GO

/****** Object:  StoredProcedure [dbo].[spInsertOrgEncryptPIN]    Script Date: 4/20/2015 4:06:47 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO


CREATE Procedure [dbo].[spInsertOrgEncryptPIN]
	(
	    @OrgId nvarchar(150),
	    @PIN varchar(50)
	)
AS
BEGIN

	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
	UPDATE [dbo].[TLSCertificate]
	SET  [EncryptedPIN] = EncryptByKey(Key_GUID('PIN_KEY'),@PIN)
	WHERE [OrgId] = @OrgId

END

GO


