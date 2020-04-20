IF NOT EXISTS (SELECT *
FROM sys.server_principals
WHERE name='DBAdmin')
        BEGIN
    RAISERROR ('User login DBAdmin not found',16,1)
END
        ELSE
        BEGIN
    PRINT 'User login DBAdmin found'
END