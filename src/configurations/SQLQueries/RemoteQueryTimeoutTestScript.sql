IF EXISTS (SELECT [name], [value], [value_in_use]
FROM [master].[sys].[configurations]
WHERE NAME LIKE 'remote query%' AND value_in_use > 0
)
BEGIN
    RAISERROR ('The remote query timeout value is greater than zero',16,1)
END
        ELSE
        BEGIN
    PRINT 'The remote query timeout value is zero'
END