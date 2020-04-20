USE Master
        GO
EXEC sp_configure 'remote access', '0'
        GO
RECONFIGURE
        GO