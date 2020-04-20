USE [msdb]
GO
IF EXISTS (SELECT [sysoperators].name, [sysoperators].enabled, [sysoperators].pager_days, [sysoperators].weekday_pager_start_time, [sysoperators].weekday_pager_end_time
FROM dbo.sysoperators
WHERE sysoperators.name = N'DBA Team' AND sysoperators.enabled = 1 AND sysoperators.pager_days = 62 AND sysoperators.weekday_pager_start_time = 080000 AND sysoperators.weekday_pager_end_time = 170000)

BEGIN
    PRINT 'DBA Team operator schedule exists'
END
ELSE
BEGIN
    RAISERROR('DBA Team operator schedule does not exist',16,1)
END
