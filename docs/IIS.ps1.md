---
external help file: -help.xml
Module Name:
online version: https://public.cyber.mil/stigs/
schema: 2.0.0
---

# IIS.ps1

## SYNOPSIS

This script will compile a DSC MOF configuration file.

## SYNTAX

```PowerShell
IIS.ps1 [[-Destination] <String>] [<CommonParameters>]
```

## DESCRIPTION

Run this script to create a Desired State Configuration MOF file.

## EXAMPLES

### EXAMPLE 1

```PowerShell
IIS -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose
```

This example will compile a MOF file from the 'IIS' DSC onfiguration script.

## PARAMETERS

### -Destination

Output path for the compiled MOF file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario.
Carefully review all configuration values before deployment.

Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides.
Each 'V' number corresponds to a STIG finding.

The following items should be reviewed for relevance to the organization's IIS security requirements.
Many items can be covered with OS-level STIG configurations or with procedures and operating policies:

- V-76815 The IIS 8.5 website document directory must be in a separate partition from the IIS 8.5 websites system files
- V-76865 The IIS 8.5 website must have a unique application pool.
- V-76767 - The File System Object component must be disabled on the IIS 8.5 web server
- V-76717 - Java software installed on a production IIS 8.5 web server must be limited to .class files and the Java Virtual Machine
- V-76705 - All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server
- V-76751 - The IIS 8.5 web server must not be running on a system providing any other role
- V-76753 - The Internet Printing Protocol (IPP) must be disabled on the IIS 8.5 web server
- V-76759 - An IIS 8.5 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version
- V-76761 - A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version
- V-76763 - The IIS 8.5 web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs)
- V-76765 - All accounts installed with the IIS 8.5 web server software and tools must have passwords assigned and default passwords changed
- V-76719 - IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts
- V-76721 - The IIS 8.5 web server must separate the hosted applications from hosted web server management functionality
- V-76743 - The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications
- V-76679 - The IIS 8.5 web server remote authors or content providers must only use secure encrypted logons and connections to upload web server content
- V-76739 - Remote access to the IIS 8.5 web server must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements
- V-76749 - Access to web administration tools must be restricted to the web manager and the web managers designees
- V-76699 - The IIS 8.5 web server must not perform user management for hosted applications
- V-76701 - The IIS 8.5 web server must only contain functions necessary for operation
- V-76707 - The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 8.5 server
- V-76709 - The IIS 8.5 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation
- V-76715 - The IIS 8.5 web server must perform RFC 5280-compliant certification path validation
- V-76729 - The IIS 8.5 web server must augment re-creation to a stable and known baseline
- V-76697 - The log data and records from the IIS 8.5 web server must be backed up onto a different system or media
- V-76691 - The IIS 8.5 web server log files must only be accessible by privileged users
- V-76695 - The log information from the IIS 8.5 web server must be protected from unauthorized deletion
- V-76693 - The log information from the IIS 8.5 web server must be protected from unauthorized modification
- V-76703 - The IIS 8.5 web server must not be both a website server and a proxy server

Author: Mike Nickerson

## RELATED LINKS

[https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)

[https://www.stigviewer.com/stig/iis_8.5_server/](https://www.stigviewer.com/stig/iis_8.5_server/)
