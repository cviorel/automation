ALTER LOGIN [sa] WITH PASSWORD=N'password'
        GO
ALTER LOGIN sa DISABLE;
        GO
ALTER LOGIN sa WITH NAME = [DBAdmin];
        GO