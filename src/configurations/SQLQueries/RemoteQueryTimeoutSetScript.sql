USE Master
        GO
EXEC sp_configure 'remote query timeout', '0'
        GO
RECONFIGURE
        GO