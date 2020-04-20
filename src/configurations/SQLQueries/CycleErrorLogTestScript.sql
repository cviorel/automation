IF NOT EXISTS (SELECT [job_id], [name]
FROM [msdb].[dbo].[sysjobs]
WHERE name = 'Email SQL Agent Job History')
        BEGIN
    RAISERROR ('Email SQL Agent Job History does not exist',16,1)
END
        ELSE
        BEGIN
    PRINT 'Email SQL Agent Job History exists'
END