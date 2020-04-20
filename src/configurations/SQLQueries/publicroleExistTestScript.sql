USE [master]
        GO
IF (SELECT COUNT([server_principals].NAME)
FROM sys.server_principals
WHERE NAME = 'publicrole' ) = 0

        BEGIN
    RAISERROR('publicrole does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'publicrole exists'
END