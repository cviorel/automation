REVOKE VIEW ANY DATABASE FROM PUBLIC AS [DBAdmin]
GO

USE [master]
        GO
REVOKE EXECUTE ON [sys].[xp_sscanf] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_fixeddrives] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_qv] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_repl_convert_encrypt_sysadmin_wrapper] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_fileexist] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_dirtree] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_getnetname] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_sprintf] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_revokelogin] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_msver] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_replposteor] TO [public] AS [dbo]
REVOKE EXECUTE ON [sys].[xp_grantlogin] TO [public] AS [dbo]
REVOKE EXECUTE ON [xp_regread] TO [public] AS [dbo]
REVOKE EXECUTE ON [xp_regwrite] TO [public] AS [dbo]
REVOKE EXECUTE ON [xp_regdeletekey] TO [public] AS [dbo]
REVOKE EXECUTE ON [xp_regdeletevalue] TO [public] AS [dbo]
REVOKE EXECUTE ON [xp_instance_regread] TO [public] AS [dbo]
        GO