USE [certDB]
GO

/****** Object:  Index [NonClusteredIndex-OrgId]    Script Date: 5/7/2015 1:12:53 PM ******/
CREATE UNIQUE NONCLUSTERED INDEX [NonClusteredIndex-OrgId] ON [dbo].[TLSCertificate]
(
	[OrgId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO


