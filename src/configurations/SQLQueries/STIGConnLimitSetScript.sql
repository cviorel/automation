CREATE TRIGGER SQL_STIG_Connection_Limit_trigger ON ALL SERVER
        FOR LOGON
        AS
        BEGIN

    IF (SELECT COUNT(1)
    FROM sys.dm_exec_sessions
    WHERE is_user_process = 1
        AND original_login_name = ORIGINAL_LOGIN()
                ) > 500
            BEGIN
        PRINT 'The login [' + ORIGINAL_LOGIN() + '] has exceeded the concurrent session limit.'
        ROLLBACK;
    END

END;
        GO

DISABLE TRIGGER [SQL_STIG_Connection_Limit_trigger] ON ALL SERVER
GO