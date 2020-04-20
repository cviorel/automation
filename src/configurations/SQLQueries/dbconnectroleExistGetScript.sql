USE [master]
        GO
SELECT [server_principals].NAME
FROM sys.server_principals
WHERE NAME = 'dbconnectrole'