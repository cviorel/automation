USE [msdb]
        GO

/****** Object:  Job [TDE Databases]    Script Date: 10/15/2015 4:45:36 PM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 10/15/2015 4:45:36 PM ******/
IF NOT EXISTS (SELECT name
FROM msdb.dbo.syscategories
WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
        BEGIN
    EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'TDE Databases',
                @enabled=0,
                @notify_level_eventlog=2,
                @notify_level_email=0,
                @notify_level_netsend=0,
                @notify_level_page=0,
                @delete_level=0,
                @description=N'No description available.',
                @category_name=N'[Uncategorized (Local)]',
                @owner_login_name=N'DBAdmin', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Run TDE Loop]    Script Date: 10/15/2015 4:45:36 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Run TDE Loop',
                @step_id=1,
                @cmdexec_success_code=0,
                @on_success_action=1,
                @on_success_step_id=0,
                @on_fail_action=2,
                @on_fail_step_id=0,
                @retry_attempts=0,
                @retry_interval=0,
                @os_run_priority=0, @subsystem=N'TSQL',
                @command=N'	declare @i int --iterator
            declare @iRwCnt int --rowcount
            declare @sValue nvarchar(150)
            declare @statement nvarchar(300)
            set @i = 1 --initialize
            create table #tbl(ID int identity(1,1), Value nvarchar(150))

            insert into #tbl(Value)
            select top 3 name from sys.databases where
            database_id > 4 and is_in_standby = 0 and
            state_desc = ''ONLINE'' and is_encrypted = 0

                set @iRwCnt = @@ROWCOUNT
                while @i <= @iRwCnt
                    begin
                    select @sValue = Value from #tbl where ID = @i
                    -- Turn on ENCRYPTION in the target database
                        set @statement = ''USE ['' + @sValue + ''];CREATE DATABASE ENCRYPTION KEY
                            WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE ORG_TDE;''
                        EXEC(@statement)
                        PRINT @statement
                        set @statement = ''ALTER DATABASE [''+ @sValue + ''] SET ENCRYPTION ON;''
                        EXEC(@statement)
                        PRINT @statement
                        set @i = @i + 1
                    end
            drop table #tbl',
                @database_name=N'master',
                @flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'Evening 2000 til Midnight Every Night',
                @enabled=1,
                @freq_type=4,
                @freq_interval=1,
                @freq_subday_type=8,
                @freq_subday_interval=1,
                @freq_relative_interval=0,
                @freq_recurrence_factor=0,
                @active_start_date=20121103,
                @active_end_date=99991231,
                @active_start_time=200000,
                @active_end_time=235959,
                @schedule_uid=N'1283cb42-43a0-4bc6-a25c-984b007c9952'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

        GO