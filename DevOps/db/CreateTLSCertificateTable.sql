/*
Deployment script for certDB
*/
GO
CREATE TABLE [dbo].[TLSCertificate] (
    [Id]                       INT             IDENTITY(1,1) NOT NULL,
    [VendorId]                 VARCHAR (150)   NULL,
    [OrganizationName]         VARCHAR (150)   NULL,
    [PIN]                      NVARCHAR (50)   NULL,
    [EncryptedPIN]             VARBINARY (MAX) NULL,
    [PrivateKeyEncryption]     VARBINARY (MAX) NULL,
    [PrivateKeySigning]        VARBINARY (MAX) NULL,
    [LastPrivateKeyEncryption] VARBINARY (MAX) NULL,
    [LastEncryptionPIN]        NVARCHAR (50)   NULL,
    [LastCertReplaceDate]      DATETIME2 (7)   NULL,
    [DateCreated]              DATETIME2 (7)   NULL,
    [CreatedBy]                NVARCHAR (50)   NULL,
    [DateModified]             DATETIME2 (7)   NULL,
    [ModifiedBy]               NVARCHAR (50)   NULL,
    [OrgId]                    NVARCHAR (50)   NULL,
    [ProfileName]              NVARCHAR (150)  NULL
    PRIMARY KEY CLUSTERED ([Id] ASC)
);
