USE [msdb]
        GO

BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
BEGIN
    EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'Email SQL Agent Job History',
                @enabled=0,
                @notify_level_eventlog=2,
                @notify_level_email=2,
                @notify_level_netsend=0,
                @notify_level_page=0,
                @delete_level=0,
                @description=N'No description available.',
                @category_name=N'[Uncategorized (Local)]',
                @owner_login_name=N'DBAdmin',
                @notify_email_operator_name=N'DBA Team', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Create and Email List]    Script Date: 10/15/2015 4:44:31 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Create and Email List',
                @step_id=1,
                @cmdexec_success_code=0,
                @on_success_action=1,
                @on_success_step_id=0,
                @on_fail_action=2,
                @on_fail_step_id=0,
                @retry_attempts=0,
                @retry_interval=0,
                @os_run_priority=0, @subsystem=N'TSQL',
                @command=N'EXEC msdb.dbo.sp_send_dbmail
            @profile_name = ''Database Mail''
        , @recipients = ''dbateam@corp.com''
        , @subject = ''SQL Agent Job History''
        , @query = ''select job_name, run_datetime, run_duration
        from
        (
            select job_name, run_datetime,
                SUBSTRING(run_duration, 1, 2) + '''':'''' + SUBSTRING(run_duration, 3, 2) + '''':'''' +
                SUBSTRING(run_duration, 5, 2) AS run_duration
            from
            (
                select DISTINCT
                    j.name as job_name,
                    run_datetime = CONVERT(DATETIME, RTRIM(run_date)) +
                        (run_time * 9 + run_time % 10000 * 6 + run_time % 100 * 10) / 216e4,
                    run_duration = RIGHT(''''000000'''' + CONVERT(varchar(6), run_duration), 6)
                from msdb..sysjobhistory h
                inner join msdb..sysjobs j
                on h.job_id = j.job_id
                where j.name not like ''''syspolicy_purge_history''''
            ) t
        ) t
        order by job_name, run_datetime''
        , @attach_query_result_as_file = 1
        , @query_attachment_filename = ''SQL Agent Job History.txt'';
        Go',
                @database_name=N'master',
                @flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'Daily 7AM',
                @enabled=1,
                @freq_type=4,
                @freq_interval=1,
                @freq_subday_type=1,
                @freq_subday_interval=0,
                @freq_relative_interval=0,
                @freq_recurrence_factor=0,
                @active_start_date=20130709,
                @active_end_date=99991231,
                @active_start_time=70000,
                @active_end_time=235959,
                @schedule_uid=N'52807d88-7836-4eff-b805-8c2a088e2a9b'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

        GO