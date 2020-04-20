
USE [master]
        GO
SELECT [sysPrincipals].NAME, [sysObjs].NAME, [perm].permission_name, [perm].state_desc
FROM sys.database_permissions [perm] LEFT OUTER JOIN sys.all_objects [sysObjs] ON [perm].major_id = [sysObjs].OBJECT_ID INNER JOIN sys.database_principals [sysPrincipals] ON [perm].grantee_principal_id = [sysPrincipals].principal_id
WHERE sysPrincipals.Name = 'public' AND sysObjs.NAME LIKE 'xp%'