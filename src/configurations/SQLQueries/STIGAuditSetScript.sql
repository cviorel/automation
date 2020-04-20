USE [master];
        GO

/****************************************/
/* Set variables needed by setup script */
DECLARE	@auditPath VARCHAR(260), @auditGuid UNIQUEIDENTIFIER, @auditFileSize VARCHAR(4), @auditFileCount VARCHAR(4)

-- Define the directory in which audit log files reside
SET @auditPath = 'H:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'


-- Define the unique identifier for the audit
-- *** Must be the same on both nodes participating in database mirroring ***
-- Use NEWID() to generate a new ID for the audit
SET @auditGuid = NEWID()

-- Define the maximum size for a single audit file (MB)
SET @auditFileSize = 200

-- Define the number of files that should be kept online
-- Use -1 for unlimited
SET @auditFileCount = 25

/****************************************/

/* Insert the variables into a temp table so they survive for the duration of the script */
CREATE TABLE #SetupVars
(
    Variable VARCHAR(50),
    Value VARCHAR(260)
)
INSERT	INTO #SetupVars
    (Variable, Value)
VALUES
    ('auditPath', @auditPath),
    ('auditGuid', CONVERT(VARCHAR(40), @auditGuid)),
    ('auditFileSize', @auditFileSize),
    ('auditFileCount', @auditFileCount)

/****************************************/
/* Delete the audit if is currently exists */
/****************************************/

USE [master];
        GO

-- Disable the Database Audit Specification on all databases
EXEC sp_MSforeachdb '
        USE [?]
        IF EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = N''DISA_STIG_AUDIT_DATABASE_SPECIFICATION'')
        ALTER DATABASE AUDIT SPECIFICATION [DISA_STIG_AUDIT_DATABASE_SPECIFICATION] WITH (STATE = OFF)
        ';

-- Drop the Database Audit Specification from all the databases
EXEC sp_MSforeachdb '
        USE [?]
        IF EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = N''DISA_STIG_AUDIT_DATABASE_SPECIFICATION'')
        DROP DATABASE AUDIT SPECIFICATION [DISA_STIG_AUDIT_DATABASE_SPECIFICATION]
        ';

USE [master];
        GO

-- Disable the Server Audit Specification
IF EXISTS (SELECT 1
FROM sys.server_audit_specifications
WHERE name = N'DISA_STIG_AUDIT_SERVER_SPECIFICATION')
        ALTER SERVER AUDIT SPECIFICATION [DISA_STIG_AUDIT_SERVER_SPECIFICATION] WITH (STATE = OFF);

-- Drop the Server Audit Specification
IF EXISTS (SELECT 1
FROM sys.server_audit_specifications
WHERE name = N'DISA_STIG_AUDIT_SERVER_SPECIFICATION')
        DROP SERVER AUDIT SPECIFICATION [DISA_STIG_AUDIT_SERVER_SPECIFICATION];
        GO

-- Disable the Server Audit
IF EXISTS (SELECT 1
FROM sys.server_audits
WHERE name = N'DISA_STIG_AUDIT')
        ALTER SERVER AUDIT [DISA_STIG_AUDIT] WITH (STATE = OFF);
        GO

-- Drop the Server Audit
IF EXISTS (SELECT 1
FROM sys.server_audits
WHERE name = N'DISA_STIG_AUDIT')
        DROP SERVER AUDIT [DISA_STIG_AUDIT];
        GO


/****************************************/
/* Set up the SQL Server Audit          */
/****************************************/

USE [master];
        GO

/* Create the Server Audit */
DECLARE	@auditPath VARCHAR(260), @auditGuid VARCHAR(40), @auditFileSize VARCHAR(4), @auditFileCount VARCHAR(5)

SELECT @auditPath = Value
FROM #SetupVars
WHERE Variable = 'auditPath'
SELECT @auditGuid = Value
FROM #SetupVars
WHERE Variable = 'auditGuid'
SELECT @auditFileSize = Value
FROM #SetupVars
WHERE Variable = 'auditFileSize'
SELECT @auditFileCount = Value
FROM #SetupVars
WHERE Variable = 'auditFileCount'

DECLARE @createStatement	NVARCHAR(max)
SET		@createStatement = '
        CREATE SERVER AUDIT [DISA_STIG_AUDIT]
        TO FILE
        (
            FILEPATH = ''' + @auditPath + '''
            , MAXSIZE = ' + @auditFileSize + ' MB
            , MAX_ROLLOVER_FILES = ' + CASE WHEN @auditFileCount = -1 THEN 'UNLIMITED' ELSE @auditFileCount END + '
            , RESERVE_DISK_SPACE = OFF
        )
        WITH
        (
            QUEUE_DELAY = 1000
            , ON_FAILURE = SHUTDOWN
            , AUDIT_GUID = ''' + @auditGuid + '''
        )
        '

EXEC(@createStatement)

/* Turn on the Audit */
ALTER SERVER AUDIT [DISA_STIG_AUDIT]
        WITH (STATE = ON)
        GO

/* Create the server audit specifications */
CREATE SERVER AUDIT SPECIFICATION [DISA_STIG_AUDIT_SERVER_SPECIFICATION]
        FOR SERVER AUDIT [DISA_STIG_AUDIT]
            ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
            ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
            ADD (BACKUP_RESTORE_GROUP),
            ADD (AUDIT_CHANGE_GROUP),
            ADD (DBCC_GROUP),
            ADD (DATABASE_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
            ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
            ADD (SERVER_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
            ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),
            ADD (FAILED_LOGIN_GROUP),
            ADD (SUCCESSFUL_LOGIN_GROUP),
            ADD (LOGOUT_GROUP),
            ADD (DATABASE_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_CHANGE_GROUP),
            ADD (SERVER_OBJECT_CHANGE_GROUP),
            ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
            ADD (DATABASE_OPERATION_GROUP),
            ADD (SERVER_OPERATION_GROUP),
            ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP),
            ADD (LOGIN_CHANGE_PASSWORD_GROUP),
            ADD (SERVER_STATE_CHANGE_GROUP),
            ADD (DATABASE_OWNERSHIP_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP),
            ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP),
            ADD (TRACE_CHANGE_GROUP)
        WITH (STATE = ON);
        GO

/* Create the database audit specifications for each database */
EXEC sp_MSforeachdb '
        USE [?]
        IF
        (
            ( NOT EXISTS
                (
                    SELECT	1
                    FROM	sys.database_audit_specifications
                    WHERE	name=N''DISA_STIG_AUDIT_DATABASE_SPECIFICATION''
                )
            )
            AND
            (
                SELECT	is_read_only
                FROM	sys.databases
                WHERE	name = DB_NAME()
            ) = 0
        )
        CREATE DATABASE AUDIT SPECIFICATION [DISA_STIG_AUDIT_DATABASE_SPECIFICATION]
        FOR SERVER AUDIT [DISA_STIG_AUDIT]
            ADD (DATABASE_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_OPERATION_GROUP),
            ADD (DATABASE_OWNERSHIP_CHANGE_GROUP),
            ADD (DATABASE_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
            ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP)
        WITH (STATE = ON)
        '

/**********************************************
        Set up the agent job
        **********************************************/

USE [msdb];
        GO

/* Delete the job if it exists */
IF EXISTS (SELECT job_id
FROM msdb.dbo.sysjobs_view
WHERE name = N'DISA STIG Audit Specification Check')
        EXEC msdb.dbo.sp_delete_job @job_name=N'DISA STIG Audit Specification Check', @delete_unused_schedule=1
        GO

BEGIN TRANSACTION

/* Declare return code variable */
DECLARE	@ReturnCode INT
SELECT @ReturnCode = 0

/* Determine the SQL SA account name */
DECLARE @saName VARCHAR(20)
SET @saName = (SELECT name
FROM master..syslogins
WHERE sid = 0x01)

/* Create the job category */
IF NOT EXISTS (SELECT name
FROM msdb.dbo.syscategories
WHERE name=N'DISA STIG Audit' AND category_class=1)
        BEGIN
    EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'DISA STIG Audit'
    IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
END

/* Create the job */
DECLARE @jobId BINARY(16)
EXEC @ReturnCode = msdb.dbo.sp_add_job @job_name='DISA STIG Audit Specification Check',
            @enabled=1,
            @notify_level_eventlog=0,
            @notify_level_email=0,
            @notify_level_netsend=0,
            @notify_level_page=0,
            @delete_level=0,
            @description=N'No description available.',
            @category_name=N'DISA STIG Audit',
            @owner_login_name=@saName,
            @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

/* Create the job step */
EXEC	@ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobid,
                @step_name=N'DISA STIG Audit Specification Check',
                @step_id=1,
                @cmdexec_success_code=0,
                @on_success_action=1,
                @on_success_step_id=0,
                @on_fail_action=2,
                @on_fail_step_id=0,
                @retry_attempts=0,
                @retry_interval=0,
                @os_run_priority=0,
                @subsystem=N'TSQL',
                @command=N'EXEC sp_MSforeachdb ''
        USE [?];
        IF
        (
            ( NOT EXISTS
                (
                    SELECT	1
                    FROM	sys.database_audit_specifications
                    WHERE	name=N''''DISA_STIG_AUDIT_DATABASE_SPECIFICATION''''
                )
            )
            AND
            (
                SELECT	is_read_only
                FROM	sys.databases
                WHERE	name = DB_NAME()
            ) = 0
        )
        CREATE DATABASE AUDIT SPECIFICATION [DISA_STIG_AUDIT_DATABASE_SPECIFICATION]
        FOR SERVER AUDIT [DISA_STIG_AUDIT]
            ADD (DATABASE_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
            ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_OPERATION_GROUP),
            ADD (DATABASE_OWNERSHIP_CHANGE_GROUP),
            ADD (DATABASE_PERMISSION_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
            ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
            ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_CHANGE_GROUP),
            ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP)
        WITH (STATE = ON)
        ''',
            @database_name=N'master',
            @flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

/* Set the agent job start step */
EXEC	@ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1

/* Create the agent job schedule */
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC	@ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId,
                @name=N'DISA STIG Audit Specification Check',
                @enabled=1,
                @freq_type=4,
                @freq_interval=1,
                @freq_subday_type=1,
                @freq_subday_interval=0,
                @freq_relative_interval=0,
                @freq_recurrence_factor=0,
                @active_start_date=20131003,
                @active_end_date=99991231,
                @active_start_time=170000,
                @active_end_time=235959
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

/* Add the job server to the agent job */
EXEC	@ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

COMMIT TRANSACTION
GOTO EndSave

QuitWithRollback:
IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION

EndSave:

        GO

/**********************************************
        Set up the agent alert
**********************************************/

USE [msdb];
        GO

/* Delete the alert if it exists */
IF EXISTS (SELECT name
FROM msdb.dbo.sysalerts
WHERE name = N'Database Was Restored')
        EXEC msdb.dbo.sp_delete_alert @name=N'Database Was Restored'

/* Create the alert */
EXEC	msdb.dbo.sp_add_alert @name='Database Was Restored',
                @message_id=18267,
                @severity=0,
                @enabled=1,
                @delay_between_responses=0,
                @include_event_description_in=0,
                @category_name=N'[Uncategorized]',
                @job_name=N'DISA STIG Audit Specification Check'
        GO

/* Clean up */
DROP TABLE #SetupVars