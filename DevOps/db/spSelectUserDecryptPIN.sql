USE [certDB]
GO
/****** Object:  StoredProcedure [dbo].[spSelectUserDecryptPIN]    Script Date: 4/29/2015 11:03:34 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
ALTER Procedure [dbo].[spSelectUserDecryptPIN]
	(
	@Email nvarchar(100)
	)
AS
BEGIN
	
--	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
--	Select CONVERT(varchar, DecryptByKey([EncryptedPIN])) AS 'Decrypted PIN' FROM [dbo].[Certificate]
--	Where [EmailAS1] = @Email

	SELECT PIN FROM [CertDB].[dbo].[Certificate] WHERE [EmailAS1] = @Email
	
END
