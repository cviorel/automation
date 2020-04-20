USE [master]
        GO
IF (SELECT COUNT(*)
FROM sys.server_principals INNER JOIN sys.server_permissions ON grantee_principal_id = [server_principals].principal_id
WHERE [server_principals].NAME = 'dbconnectrole' AND [server_permissions].permission_name = 'CONNECT SQL') = 0

        BEGIN
    RAISERROR('CONNECT SQL permission for dbconnectrole does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'CONNECT SQL permission for dbconnectrole exists'
END