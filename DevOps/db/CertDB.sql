USE [certDB]
GO
/****** Object:  StoredProcedure [dbo].[spInsertOrgEncryptPIN]    Script Date: 4/20/2015 4:16:54 PM ******/
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
/****** Object:  StoredProcedure [dbo].[spInsertUserEncryptPIN]    Script Date: 4/20/2015 4:16:54 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[spInsertUserEncryptPIN]
	(@Email nvarchar(100),
	@PIN varchar(50))
AS
BEGIN
	
	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
	UPDATE [dbo].[Certificate] 
	SET  [EncryptedPIN] = EncryptByKey(Key_GUID('PIN_KEY'),@PIN)
	WHERE [EmailAS1] = @Email
END


GO
/****** Object:  StoredProcedure [dbo].[spSelectOrgDecryptPIN]    Script Date: 4/20/2015 4:16:54 PM ******/
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
/****** Object:  StoredProcedure [dbo].[spSelectUserDecryptPIN]    Script Date: 4/20/2015 4:16:54 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE Procedure [dbo].[spSelectUserDecryptPIN]
	(
	@Email nvarchar(100)
	)
AS
BEGIN
	
	OPEN SYMMETRIC KEY PIN_KEY DECRYPTION BY CERTIFICATE PIN_CERT;
	Select CONVERT(varchar, DecryptByKey([EncryptedPIN])) AS 'Decrypted PIN' FROM [dbo].[Certificate]
	Where [EmailAS1] = @Email
	
END


GO
/****** Object:  Table [dbo].[Certificate]    Script Date: 4/20/2015 4:16:54 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Certificate](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[PracticeId] [int] NULL,
	[EmailAS1] [nvarchar](100) NULL,
	[PIN] [nvarchar](50) NULL,
	[EncryptedPIN] [varbinary](max) NULL,
	[PublicKeyEncryption] [varbinary](max) NULL,
	[EncryptionCertExpDate] [datetime2](7) NULL,
	[PublicKeySigning] [varbinary](max) NULL,
	[SigningCertExpDate] [datetime2](7) NULL,
	[PrivateKeyEncryption] [varbinary](max) NULL,
	[PrivateKeySigning] [varbinary](max) NULL,
	[EncryptionPIN] [nvarchar](50) NULL,
	[SigningPIN] [nvarchar](50) NULL,
	[LastPrivateKeyEncryption] [varbinary](max) NULL,
	[LastEcryptionPIN] [nvarchar](50) NULL,
	[LastCertReplaceDate] [datetime2](7) NULL,
	[DateCreated] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](50) NULL,
	[DateModified] [datetime2](7) NULL,
	[ModifiedBy] [nvarchar](50) NULL,
	[ProfileName] [nvarchar](150) NULL,
	[IsExternal] [bit] NULL,
 CONSTRAINT [PK_Certificate] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
 CONSTRAINT [IX_Certificate_EmailAS1] UNIQUE NONCLUSTERED 
(
	[EmailAS1] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[CertificateProfile]    Script Date: 4/20/2015 4:16:54 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[CertificateProfile](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[ProfileName] [varchar](150) NULL,
	[SigningCertSerialNumber] [varchar](150) NULL,
	[CRLURL] [varchar](150) NULL,
	[AIAPath] [varchar](150) NULL,
	[CertPolicyOID] [varchar](150) NULL,
	[LOAPolicyOID] [varchar](150) NULL,
	[CategoryOID] [varchar](150) NULL,
	[EnhancedKeyUsageOID] [varchar](300) NULL,
	[DateCreated] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](50) NULL,
	[DateModified] [datetime2](7) NULL,
	[ModifiedBy] [nvarchar](50) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[TLSCertificate]    Script Date: 4/20/2015 4:16:54 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[TLSCertificate](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[VendorId] [varchar](150) NULL,
	[OrganizationName] [varchar](150) NULL,
	[PIN] [nvarchar](50) NULL,
	[EncryptedPIN] [varbinary](max) NULL,
	[PrivateKeyEncryption] [varbinary](max) NULL,
	[PrivateKeySigning] [varbinary](max) NULL,
	[LastPrivateKeyEncryption] [varbinary](max) NULL,
	[LastEncryptionPIN] [nvarchar](50) NULL,
	[LastCertReplaceDate] [datetime2](7) NULL,
	[DateCreated] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](50) NULL,
	[DateModified] [datetime2](7) NULL,
	[ModifiedBy] [nvarchar](50) NULL,
	[OrgId] [nchar](50) NULL,
	[ProfileName] [nvarchar](150) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
ALTER TABLE [dbo].[Certificate] ADD  DEFAULT ((0)) FOR [IsExternal]
GO
ALTER TABLE [dbo].[CertificateProfile] ADD  DEFAULT (getdate()) FOR [DateCreated]
GO
ALTER TABLE [dbo].[CertificateProfile] ADD  DEFAULT (getdate()) FOR [DateModified]
GO
