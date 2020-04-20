IF NOT EXISTS (SELECT [job_id], [name]
FROM [msdb].[dbo].[sysjobs]
WHERE name = 'TDE Databases')
        BEGIN
    RAISERROR ('TDE Databases does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'TDE Databases exists'
END