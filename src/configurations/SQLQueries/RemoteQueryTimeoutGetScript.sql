SELECT [name], [value], [value_in_use]
FROM [master].[sys].[configurations]
WHERE NAME LIKE 'remote query%'