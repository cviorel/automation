USE [master]
        GO
IF (SELECT COUNT(*)
FROM sys.server_principals INNER JOIN sys.server_permissions ON grantee_principal_id = [server_principals].principal_id
WHERE [server_principals].NAME = 'publicrole' AND [server_permissions].permission_name = 'VIEW ANY DATABASE') = 0

        BEGIN
    RAISERROR('VIEW ANY DATABASE permission for publicrole does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'VIEW ANY DATABASE permission for publicrole exists'
END