USE [master]
GO
IF EXISTS (SELECT [server_triggers].name, [server_triggers].is_disabled
FROM sys.server_triggers
WHERE server_triggers.name = 'SQL_STIG_Connection_Limit_trigger' AND server_triggers.is_disabled = 1)

BEGIN
    PRINT 'SQL_STIG_Connection_Limit_trigger exists and is disabled.'
END
ELSE
BEGIN
    RAISERROR ('SQL_STIG_Connection_Limit_trigger does not exist or is not disabled.',16,1)
END