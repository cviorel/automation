SELECT TOP (1000) [AgentId]
      ,[LCMVersion]
      ,[NodeName]
      ,[IPAddress]
      ,[ConfigurationNames]
  FROM [DSC].[dbo].[RegistrationData]
  ORDER BY NodeName DESC