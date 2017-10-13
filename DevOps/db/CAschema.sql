/****** Object:  Database [certDB]    Script Date: 9/19/2014 2:34:39 PM ******/
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [certDB].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [certDB] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [certDB] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [certDB] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [certDB] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [certDB] SET ARITHABORT OFF 
GO
ALTER DATABASE [certDB] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [certDB] SET AUTO_CREATE_STATISTICS ON 
GO
ALTER DATABASE [certDB] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [certDB] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [certDB] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [certDB] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [certDB] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [certDB] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [certDB] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [certDB] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [certDB] SET  DISABLE_BROKER 
GO
ALTER DATABASE [certDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [certDB] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [certDB] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [certDB] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [certDB] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [certDB] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [certDB] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [certDB] SET RECOVERY FULL 
GO
ALTER DATABASE [certDB] SET  MULTI_USER 
GO
ALTER DATABASE [certDB] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [certDB] SET DB_CHAINING OFF 
GO
ALTER DATABASE [certDB] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [certDB] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO
USE [certDB]
GO
/****** Object:  User [sesrdssa]    Script Date: 9/19/2014 2:34:39 PM ******/
CREATE USER [sesrdssa] FOR LOGIN [sesrdssa] WITH DEFAULT_SCHEMA=[dbo]
GO
ALTER ROLE [db_owner] ADD MEMBER [sesrdssa]
GO
/****** Object:  StoredProcedure [dbo].[spInsertUserEncryptPIN]    Script Date: 9/19/2014 2:34:39 PM ******/
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
/****** Object:  StoredProcedure [dbo].[spSelectUserDecryptPIN]    Script Date: 9/19/2014 2:34:39 PM ******/
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
/****** Object:  Table [dbo].[Audit]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Audit](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[CertificaterRowId] [int] NULL,
	[ActorId] [int] NULL,
	[ActionDate] [datetime2](7) NULL,
	[ActionDescription] [nvarchar](50) NULL,
 CONSTRAINT [PK_Audit] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[ca_export_stage]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[ca_export_stage](
	[Id] [int] IDENTITY(715000,1) NOT NULL,
	[PracticeName] [nvarchar](100) NOT NULL,
	[EmailAS1] [nvarchar](100) NOT NULL,
	[PIN] [nvarchar](50) NULL,
	[PublicKeyEncryption] [varbinary](max) NULL,
	[PublicKeySigning] [varbinary](max) NULL,
	[PrivateKeyEncryption] [varbinary](max) NULL,
	[PrivateKeySigning] [varbinary](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[Certificate]    Script Date: 9/19/2014 2:34:39 PM ******/
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
/****** Object:  Table [dbo].[crisp_export_stage]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[crisp_export_stage](
	[Id] [int] IDENTITY(715000,1) NOT NULL,
	[PracticeName] [nvarchar](100) NOT NULL,
	[EmailAS1] [nvarchar](100) NOT NULL,
	[PIN] [nvarchar](50) NULL,
	[EncryptedPIN] [varbinary](max) NULL,
	[PublicKeyEncryption] [varbinary](max) NULL,
	[PublicKeySigning] [varbinary](max) NULL,
	[PrivateKeyEncryption] [varbinary](max) NULL,
	[PrivateKeySigning] [varbinary](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[directaddress_export_test]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[directaddress_export_test](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[PracticeId] [int] NULL,
	[EmailAS1] [nvarchar](100) NULL,
	[PIN] [varchar](50) NULL,
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
 CONSTRAINT [PK_directaddress_export_test] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[elinc_backup_stage]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[elinc_backup_stage](
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
	[ModifiedBy] [nvarchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  DdlTrigger [rds_deny_backups_trigger]    Script Date: 9/19/2014 2:34:39 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TRIGGER [rds_deny_backups_trigger] ON DATABASE WITH EXECUTE AS 'dbo' FOR
 ADD_ROLE_MEMBER, GRANT_DATABASE AS BEGIN
   SET ANSI_PADDING ON;
 
   DECLARE @data XML;
   DECLARE @user SYSNAME;
   DECLARE @role SYSNAME;
   DECLARE @type SYSNAME;
   DECLARE @sql NVARCHAR(MAX);
   DECLARE @permissions TABLE(name SYSNAME PRIMARY KEY);
   
   SELECT @data = EVENTDATA();
   SELECT @type = @data.value('(/EVENT_INSTANCE/EventType)[1]', 'SYSNAME');
    
   IF @type = 'ADD_ROLE_MEMBER' BEGIN
      SELECT @user = @data.value('(/EVENT_INSTANCE/ObjectName)[1]', 'SYSNAME'),
       @role = @data.value('(/EVENT_INSTANCE/RoleName)[1]', 'SYSNAME');

      IF @role IN ('db_owner', 'db_backupoperator') BEGIN
         SELECT @sql = 'DENY BACKUP DATABASE, BACKUP LOG TO ' + QUOTENAME(@user);
         EXEC(@sql);
      END
   END ELSE IF @type = 'GRANT_DATABASE' BEGIN
      INSERT INTO @permissions(name)
      SELECT Permission.value('(text())[1]', 'SYSNAME') FROM
       @data.nodes('/EVENT_INSTANCE/Permissions/Permission')
      AS DatabasePermissions(Permission);
      
      IF EXISTS (SELECT * FROM @permissions WHERE name IN ('BACKUP DATABASE',
       'BACKUP LOG'))
         RAISERROR('Cannot grant backup database or backup log', 15, 1) WITH LOG;       
   END
END

GO
SET ANSI_NULLS OFF
GO
SET QUOTED_IDENTIFIER OFF
GO
ENABLE TRIGGER [rds_deny_backups_trigger] ON DATABASE
GO
USE [master]
GO
ALTER DATABASE [certDB] SET  READ_WRITE 
GO
