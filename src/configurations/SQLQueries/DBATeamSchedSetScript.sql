USE [msdb] ;
GO

EXEC dbo.sp_update_operator
@name = N'DBA Team',
@enabled = 1,
@weekday_pager_start_time = 080000,
@weekday_pager_end_time = 170000,
@pager_days = 62 ;
GO