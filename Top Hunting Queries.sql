Malicious PowerShell: This query helps identify instances where PowerShell is used for malicious purposes, such as to download and execute malware.
DeviceProcessEvents
| where ActionType == "ProcessCreate" and FileName == "powershell.exe" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and CommandLine contains "-encodedCommand"

PowerShell? More like PowerHell! This query will catch all those sneaky bastards who think they can hide behind PowerShell.
DeviceProcessEvents
| where ActionType == "ProcessCreate" and FileName == "powershell.exe" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and CommandLine contains "-encodedCommand"

Suspicious Office Macros: This query helps identify instances where Microsoft Office macros are used to deliver malware or initiate malicious activities.
DeviceProcessEvents
| where ActionType == "OfficeMacroExecution" and (FileName contains "docm" or FileName contains "xlsm" or FileName contains "pptm") and MacroType == "VbaMacro" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll")

Don't trust those Microsoft Office macros. This query will help you identify when those pesky macros try to sneak in some malware.
DeviceProcessEvents
| where ActionType == "OfficeMacroExecution" and (FileName contains "docm" or FileName contains "xlsm" or FileName contains "pptm") and MacroType == "VbaMacro" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll")

Lateral Movement: This query helps identify instances where attackers are attempting to move laterally across the network by compromising additional systems.
DeviceProcessEvents
| where ActionType == "ProcessCreate" and InitiatingProcessFileName == "services.exe" and InitiatingProcessCommandLine contains "lsass.exe"
| join kind=inner (DeviceProcessEvents
| where ActionType == "ProcessCreate" and InitiatingProcessFileName == "lsass.exe") on DeviceId
| where $left.InitiatingProcessParentId == $right.ProcessId and $left.InitiatingProcessCommandLine != $right.CommandLine

Credential Theft: This query helps identify instances where attackers are attempting to steal user credentials.
DeviceProcessEvents
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "lsass.exe" and InitiatingProcessFileName != "services.exe" and (CommandLine contains "mimikatz" or CommandLine contains "gsecdump")

Don't let those pesky hackers steal your credentials! Use this query to catch them in the act.
DeviceProcessEvents
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "lsass.exe" and InitiatingProcessFileName != "services.exe" and (CommandLine contains "mimikatz" or CommandLine contains "gsecdump")

Data Exfiltration: This query helps identify instances where sensitive data is being exfiltrated from the network.
DeviceNetworkEvents
| where ActionType == "NetworkFlow" and RemoteUrl !contains ".microsoft.com" and RemoteUrl !contains ".windowsupdate.com" and RemoteUrl !contains ".office.com"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".zip" or FileName contains ".rar" or FileName contains ".7z" or FileName contains ".tar" or FileName contains ".cab" or FileName contains ".doc" or FileName contains ".xls" or FileName contains ".ppt" or FileName contains ".pdf" or FileName contains ".txt" or FileName contains ".csv" or FileName contains ".json" or FileName contains ".xml" or FileName contains ".sql" or FileName contains ".bak" or FileName contains ".mdb")

Don't let your sensitive data leave your network! This query will help you identify when someone's trying to exfiltrate your data.
DeviceNetworkEvents
| where ActionType == "NetworkFlow" and RemoteUrl !contains ".microsoft.com" and RemoteUrl !contains ".windowsupdate.com" and RemoteUrl !contains ".office.com"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".zip" or FileName contains ".rar" or FileName contains ".7z" or FileName contains ".tar" or FileName contains ".cab" or FileName contains ".doc" or FileName contains ".xls" or FileName contains ".ppt" or FileName contains ".pdf" or FileName contains ".txt" or FileName contains ".csv" or FileName contains ".json" or FileName contains ".xml" or FileName contains ".sql" or FileName contains ".bak" or FileName contains ".mdb")

Malicious External Emails: This query helps identify instances where external emails are suspected of containing malware or phishing attempts.
EmailEvents
| where IsExternalSender == true and ThreatSeverity == "High" and Subject contains "Phishing"
| join kind=inner FileAttachmentEvents on EventTime, IncidentId
| where ThreatSeverity == "High" and FileType == "Executable"

Watch out for those malicious emails from outside your organization! This query will help you catch any malware or phishing attempts.
EmailEvents
| where IsExternalSender == true and ThreatSeverity == "High" and Subject contains "Phishing"
| join kind=inner FileAttachmentEvents on EventTime, IncidentId
| where ThreatSeverity == "High" and FileType == "Executable"

Suspicious User Behavior: This query helps identify instances where user behavior is suspicious or deviates from normal patterns.
DeviceBehaviorAnalytics
| where ActionType == "AnomalousUserAccountActivity" and Severity == "High"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll" or FileName contains ".bat" or FileName contains ".ps1" or FileName contains ".vbs")

Keep an eye out for suspicious user behavior! This query will help you catch any anomalies that may indicate an attack.
DeviceBehaviorAnalytics
| where ActionType == "AnomalousUserAccountActivity" and Severity == "High"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll" or FileName contains ".bat" or FileName contains ".ps1" or FileName contains ".vbs")

Suspicious Azure AD Activity: This query helps identify instances where there is suspicious activity in Azure Active Directory (Azure AD), such as unauthorized access attempts or privilege escalation.
AuditLogs
| where Category == "Authentication" and ResultType == "Failure" and ActivityDisplayName == "Sign-in error code" and ActivityErrorCode == "50126"
| join kind=inner AuditLogs on CorrelationId, DeviceId
| where Category == "User and group management" and ActivityDisplayName == "Add member to group" and TargetResources[0].ResourceType == "Microsoft.Azure.ActiveDirectory/groups"

Keep your Azure AD secure! This query will help you identify any suspicious activity, such as unauthorized access attempts or privilege escalation.
AuditLogs
| where Category == "Authentication" and ResultType == "Failure" and ActivityDisplayName == "Sign-in error code" and ActivityErrorCode == "50126"
| join kind=inner AuditLogs on CorrelationId, DeviceId
| where Category == "User and group management" and ActivityDisplayName == "Add member to group" and TargetResources[0].ResourceType == "Microsoft.Azure.ActiveDirectory/groups"

Suspicious SharePoint Activity: This query helps identify instances where there is suspicious activity in SharePoint, such as unauthorized access attempts or unusual file modifications.
AuditLogs
| where RecordType == "SharePoint" and OperationName == "Copy" and UserKey != "System Account" and SourceFileName != TargetFileName

Keep your SharePoint secure! This query will help you catch any unauthorized access attempts or unusual file modifications.
AuditLogs
| where RecordType == "SharePoint" and OperationName == "Copy" and UserKey != "System Account" and SourceFileName != TargetFileName

Malware Execution: This query helps identify instances where malware is executed on a device in your environment.
DeviceProcessEvents
| where InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe" and InitiatingProcessFileName != "outlook.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll")

Keep your devices malware-free! This query will help you identify any instances of malware execution.
DeviceProcessEvents
| where InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe" and InitiatingProcessFileName != "outlook.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".exe" or FileName contains ".dll")






















