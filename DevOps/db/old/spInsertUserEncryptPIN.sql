USE [certDB]
GO
/****** Object:  StoredProcedure [dbo].[spInsertUserEncryptPIN]    Script Date: 4/29/2015 10:59:52 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

ALTER Procedure [dbo].[spInsertUserEncryptPIN]
	(@Email nvarchar(100),
	@PIN varchar(50))
AS
BEGIN
	
	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
	UPDATE [dbo].[Certificate] 
	SET  [EncryptedPIN] = EncryptByKey(Key_GUID('PIN_KEY'),@PIN)
	WHERE [EmailAS1] = @Email
END
