USE [certDB]
GO
ALTER TABLE [dbo].[Certificate] ADD [ProfileName] nvarchar(150) DEFAULT 0
ALTER TABLE [dbo].[Certificate] ADD [IsExternal] bit DEFAULT 0
ALTER TABLE [dbo].[Certificate] ADD [IsDeleted] bit DEFAULT 0
ALTER TABLE [dbo].[TLSCertificate] ADD [IsDeleted] bit DEFAULT 0
GO
