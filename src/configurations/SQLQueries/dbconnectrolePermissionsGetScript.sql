USE [master]
        GO
SELECT *
FROM sys.server_principals INNER JOIN sys.server_permissions ON grantee_principal_id = [server_principals].principal_id
WHERE [server_principals].NAME = 'dbconnectrole' AND [server_permissions].permission_name = 'CONNECT SQL'
