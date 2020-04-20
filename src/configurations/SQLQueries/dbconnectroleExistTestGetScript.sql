USE [master]
        GO
IF (SELECT COUNT([server_principals].NAME)
FROM sys.server_principals
WHERE NAME = 'dbconnectrole' ) = 0

        BEGIN
    RAISERROR('dbconnectrole does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'dbconnectrole exists'
END