CREATE LOGIN [{0}\{1}] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english];
GO

USE [DSC]

CREATE USER [{1}] FOR LOGIN [{0}\{1}] WITH DEFAULT_SCHEMA=[db_datareader]
GO

ALTER ROLE [db_datareader] ADD MEMBER [{1}]
GO

ALTER ROLE [db_datawriter] ADD MEMBER [{1}]
GO

ALTER ROLE [db_owner] ADD MEMBER [{1}]
GO