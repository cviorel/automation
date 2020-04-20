SELECT [job_id], [name]
FROM [msdb].[dbo].[sysjobs]
WHERE name = 'Email SQL Agent Job History'