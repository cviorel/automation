IF (SELECT [name]
FROM [master].[sys].[server_audits]) != 'DISA_STIG_AUDIT'
        BEGIN
    RAISERROR ('DISA_STIG_AUDIT not found.',16,1)
END
        ELSE
        BEGIN
    PRINT 'DISA_STIG_AUDIT exists.'
END