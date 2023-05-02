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

Lateral Movement: This query helps identify instances where an attacker is attempting to move laterally within your network, such as by exploiting vulnerabilities or using stolen credentials.
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "powershell.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName == "lsass.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "lsass.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe"

Don't let attackers move laterally within your network! This query will help you catch any attempts to exploit vulnerabilities or use stolen credentials.
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "powershell.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName == "lsass.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "lsass.exe"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe"

Remote Access: This query helps identify instances where there is suspicious remote access activity, such as an attacker gaining unauthorized access to a device or network.
DeviceNetworkEvents
| where ActionType == "ConnectionEstablished" and RemoteIpAddress != "127.0.0.1" and RemoteIpAddress != "::1"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe" and InitiatingProcessFileName != "outlook.exe"

Keep an eye out for suspicious remote access activity! This query will help you catch any unauthorized access attempts.
DeviceNetworkEvents
| where ActionType == "ConnectionEstablished" and RemoteIpAddress != "127.0.0.1" and RemoteIpAddress != "::1"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where ActionType == "ProcessCreate" and InitiatingProcessFileName != "services.exe" and InitiatingProcessFileName != "svchost.exe" and InitiatingProcessFileName != "wmiprvse.exe" and InitiatingProcessFileName != "winword.exe" and InitiatingProcessFileName != "excel.exe" and InitiatingProcessFileName != "powerpnt.exe" and InitiatingProcessFileName != "outlook.exe"

Suspicious Office 365 Activity: This query helps identify instances where there is suspicious activity within Office 365, such as unusual login activity or unusual file access.
AuditLogs
| where RecordType == "Exchange" and Operation == "FolderBind" and ResultStatus == "Succeeded"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "Exchange" and Operation == "MailboxLogin" and ResultStatus == "Succeeded" and ClientIPAddress != "127.0.0.1"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "SharePoint" and Operation == "FileAccessed" and ResultStatus == "Succeeded" and ClientIPAddress != "127.0.0.1"

Keep your Office 365 environment secure! This query will help you catch any suspicious activity, such as unusual login or file access.
AuditLogs
| where RecordType == "Exchange" and Operation == "FolderBind" and ResultStatus == "Succeeded"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "Exchange" and Operation == "MailboxLogin" and ResultStatus == "Succeeded" and ClientIPAddress != "127.0.0.1"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "SharePoint" and Operation == "FileAccessed" and ResultStatus == "Succeeded" and ClientIPAddress != "127.0.0.1"

Suspicious Azure Activity: This query helps identify instances where there is suspicious activity within Azure, such as unusual login activity or resource modifications.
AuditLogs
| where ResourceProvider == "Microsoft.Compute" and (OperationName == "Microsoft.Compute/virtualMachines/read" or OperationName == "Microsoft.Compute/virtualMachines/extensions/read" or OperationName == "Microsoft.Compute/virtualMachines/extensions/write")
| join kind=inner AuditLogs on CorrelationId, UserKey
| where ResourceProvider == "Microsoft.Compute" and (OperationName == "Microsoft.Compute/virtualMachines/start" or OperationName == "Microsoft.Compute/virtualMachines/restart" or OperationName == "Microsoft.Compute/virtualMachines/deallocate")

Keep your Azure environment secure! This query will help you catch any suspicious activity, such as unusual login or resource modifications.
AuditLogs
| where ResourceProvider == "Microsoft.Compute" and (OperationName == "Microsoft.Compute/virtualMachines/read" or OperationName == "Microsoft.Compute/virtualMachines/extensions/read" or OperationName == "Microsoft.Compute/virtualMachines/extensions/write")
| join kind=inner AuditLogs on CorrelationId, UserKey
| where ResourceProvider == "Microsoft.Compute" and (OperationName == "Microsoft.Compute/virtualMachines/start" or OperationName == "Microsoft.Compute/virtualMachines/restart" or OperationName == "Microsoft.Compute/virtualMachines/deallocate")

Suspicious Endpoint Protection Activity: This query helps identify instances where there is suspicious activity related to endpoint protection, such as malware detection or unauthorized changes to security settings.
DeviceProtectionEvents
| where ActionType == "MalwareDetected" and Severity == "High" and (ActionInitiatedBy == "User" or ActionInitiatedBy == "Unknown")
| join kind=inner DeviceSecurityEvents on EventTime, DeviceId
| where ActionType == "SecurityPolicyChanged" and (NewState == "Disabled" or NewState == "Modified")

Brute Force Attack: This query helps identify instances where there is suspicious activity related to a brute force attack, such as repeated login attempts or failed authentication attempts.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure" and TimeGenerated > ago(1d)
| summarize Count=count() by UserKey, IPAddress
| where Count > 50

Don't let attackers brute force their way into your system! This query will help you catch any repeated login attempts or failed authentication attempts.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure" and TimeGenerated > ago(1d)
| summarize Count=count() by UserKey, IPAddress
| where Count > 50

Account Enumeration: This query helps identify instances where an attacker is attempting to enumerate accounts in your environment, such as by using a list of known usernames.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "AuthenticationPolicyViolation" and ResultType == "Failure" and AdditionalDetails contains "Username enumeration"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure" and TimeGenerated > ago(1d)
| summarize Count=count() by UserKey, IPAddress
| where Count > 50

Don't let attackers enumerate accounts in your environment! This query will help you catch any attempts to use a list of known usernames.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "AuthenticationPolicyViolation" and ResultType == "Failure" and AdditionalDetails contains "Username enumeration"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Authentication" and ActivityDisplayName == "Credential submitted" and ResultType == "Failure" and TimeGenerated > ago(1d)
| summarize Count=count() by UserKey, IPAddress
| where Count > 50

Data Exfiltration: This query helps identify instances where an attacker is attempting to exfiltrate data from your environment, such as by transferring large amounts of data to an external location.
DeviceFileEvents
| where ActionType == "FileCreated" and (FileName contains ".doc" or FileName contains ".docx" or FileName contains ".xls" or FileName contains ".xlsx" or FileName contains ".ppt" or FileName contains ".pptx" or FileName contains ".pdf")
| join kind=inner DeviceNetworkEvents on EventTime, DeviceId
| where ActionType == "ConnectionEstablished" and RemoteIpAddress != "127.0.0.1" and RemoteIpAddress != "::1"
| summarize TotalSize=sum(FileSize) by RemoteIpAddress
| where TotalSize > 10000000

Don't let attackers exfiltrate your data! This query will help you catch any attempts to transfer large amounts of data to an external location.
DeviceFileEvents
| where ActionType == "FileCreated" and (FileName contains ".doc" or FileName contains ".docx" or FileName contains ".xls" or FileName contains ".xlsx" or FileName contains ".ppt" or FileName contains ".pptx" or FileName contains ".pdf")
| join kind=inner Device

Suspicious PowerShell Activity: This query helps identify instances where there is suspicious activity related to PowerShell, such as the use of uncommon commands or suspicious command parameters.
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".ps1" or FileName contains ".bat" or FileName contains ".cmd" or FileName contains ".vbs" or FileName contains ".js")
| join kind=inner DeviceRegistryEvents on EventTime, DeviceId
| where RegistryValueName == "CommandLine" and RegistryValueData contains "-Command"
| summarize count() by InitiatingProcessCommandLine

Don't let attackers use PowerShell against you! This query will help you catch any suspicious activity related to PowerShell, such as the use of uncommon commands or suspicious command parameters.
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| join kind=inner DeviceFileEvents on EventTime, DeviceId
| where ActionType == "FileCreated" and (FileName contains ".ps1" or FileName contains ".bat" or FileName contains ".cmd" or FileName contains ".vbs" or FileName contains ".js")
| join kind=inner DeviceRegistryEvents on EventTime, DeviceId
| where RegistryValueName == "CommandLine" and RegistryValueData contains "-Command"
| summarize count() by InitiatingProcessCommandLine

Data Manipulation: This query helps identify instances where there is suspicious activity related to data manipulation, such as unauthorized changes to data or modifications to data access permissions.
AuditLogs
| where Category == "Data" and ActivityDisplayName == "Update"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Data" and ActivityDisplayName == "Update" and TimeGenerated > ago(1d)
| summarize count() by UserKey
| where count() > 100

Don't let attackers manipulate your data! This query will help you catch any suspicious activity related to unauthorized changes to data or modifications to data access permissions.
AuditLogs
| where Category == "Data" and ActivityDisplayName == "Update"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "Data" and ActivityDisplayName == "Update" and TimeGenerated > ago(1d)
| summarize count() by UserKey
| where count() > 100

Suspicious Azure AD Activity: This query helps identify instances where there is suspicious activity related to Azure AD, such as unusual login activity or changes to user permissions.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "Conditional Access policy evaluation" and ResultType == "Failure" and AdditionalDetails contains "Policy store read failed"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "DirectoryService" and ActivityDisplayName == "Update directory role membership" and ResultType == "Success" and TimeGenerated > ago(1d)

Don't let attackers compromise your Azure AD! This query will help you catch any suspicious activity related to unusual login activity or changes to user permissions.
AuditLogs
| where Category == "Authentication" and ActivityDisplayName == "Conditional Access policy evaluation" and ResultType == "Failure" and AdditionalDetails contains "Policy store read failed"
| join kind=inner AuditLogs on CorrelationId, UserKey
| where Category == "DirectoryService" and ActivityDisplayName == "Update directory role membership" and ResultType == "Success" and TimeGenerated > ago(1d)

Suspicious DNS Activity: This query helps identify instances where there is suspicious DNS activity, such as the use of a known malicious domain or unusual DNS requests.
DeviceNetworkEvents
| where RemoteIPAddress != "127.0.0.1" and RemoteIPAddress != "::1" and RemoteIPAddress != "fe80::1"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where InitiatingProcessFileName contains "svchost.exe" and InitiatingProcessCommandLine contains "-k NetworkService"
| join kind=inner DeviceDnsEvents on EventTime, DeviceId
| where DnsQueryStatus == "Success" and (DnsQueryName contains ".com" or DnsQueryName contains ".net" or DnsQueryName contains ".org" or DnsQueryName contains ".ru" or DnsQueryName contains ".cn")

Don't let attackers abuse your DNS! This query will help you catch any suspicious DNS activity, such as the use of a known malicious domain or unusual DNS requests.
DeviceNetworkEvents
| where RemoteIPAddress != "127.0.0.1" and RemoteIPAddress != "::1" and RemoteIPAddress != "fe80::1"
| join kind=inner DeviceProcessEvents on EventTime, DeviceId
| where InitiatingProcessFileName contains "svchost.exe" and InitiatingProcessCommandLine contains "-k NetworkService"
| join kind=inner DeviceDnsEvents on EventTime, DeviceId
| where DnsQueryStatus == "Success" and (DnsQueryName contains ".com" or DnsQueryName contains ".net" or DnsQueryName contains ".org" or DnsQueryName contains ".ru" or DnsQueryName contains ".cn")

Suspicious SharePoint Activity: This query helps identify instances where there is suspicious activity related to SharePoint, such as unusual file access or changes to file permissions.
AuditLogs
| where RecordType == "SharePoint" and Operation == "FileAccessed" and ResultStatus == "Succeeded" and (UserKey == "" or UserKey == "-")
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "SharePoint" and Operation == "UpdateListItem" and ResultStatus == "Succeeded" and TimeGenerated > ago(1d)

Suspicious Exchange Activity: This query helps identify instances where there is suspicious activity related to Exchange, such as unusual email activity or changes to mailbox permissions.
AuditLogs
| where RecordType == "Exchange" and (Operation == "SendAs" or Operation == "SendOnBehalf")
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "Exchange" and Operation == "UpdateMailbox" and ResultStatus == "Succeeded" and TimeGenerated > ago(1d)

Don't let attackers compromise your Exchange! This query will help you catch any suspicious activity related to unusual email activity or changes to mailbox permissions.
AuditLogs
| where RecordType == "Exchange" and (Operation == "SendAs" or Operation == "SendOnBehalf")
| join kind=inner AuditLogs on CorrelationId, UserKey
| where RecordType == "Exchange" and Operation == "UpdateMailbox" and ResultStatus == "Succeeded" and TimeGenerated > ago(1d)

Suspicious Microsoft Defender for Endpoint Activity: This query helps identify instances where there is suspicious activity related to Microsoft Defender for Endpoint, such as the detection of known malware or suspicious behavior.
DeviceEvents
| where Timestamp > ago(1d) and ActionType == "MalwareDetection" and Severity == "High" and (MalwareStatus == "Detected" or MalwareStatus == "PartiallyDetected")
| summarize count() by ComputerName, ThreatName
| order by count_ desc

Don't let attackers evade Microsoft Defender for Endpoint! This query will help you catch any suspicious activity related to the detection of known malware or suspicious behavior.
DeviceEvents
| where Timestamp > ago(1d) and ActionType == "MalwareDetection" and Severity == "High" and (MalwareStatus == "Detected" or MalwareStatus == "PartiallyDetected")
| summarize count() by ComputerName, ThreatName
| order by count_ desc

Suspicious Azure Sentinel Activity: This query helps identify instances where there is suspicious activity related to Azure Sentinel, such as the detection of suspicious events or the use of unusual analytics rules.
SecurityEvent
| where ProviderName == "Azure Sentinel"
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "16908289" and Level == "Warning" and TimeGenerated > ago(1d)
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "16908290" and Level == "Informational" and TimeGenerated > ago(1d)

Don't let attackers evade Azure Sentinel! This query will help you catch any suspicious activity related to the detection of suspicious events or the use of unusual analytics rules.
SecurityEvent
| where ProviderName == "Azure Sentinel"
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "16908289" and Level == "Warning" and TimeGenerated > ago(1d)
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "16908290" and Level == "Informational" and TimeGenerated > ago(1d)

Suspicious Azure Security Center Activity: This query helps identify instances where there is suspicious activity related to Azure Security Center, such as the detection of known vulnerabilities or the use of unusual security recommendations.
SecurityAlert
| where ProviderName == "Azure Security Center"
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "4658" and TimeGenerated > ago(1d)
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "4659" and TimeGenerated > ago(1d)

Don't let attackers evade Azure Security Center! This query will help you catch any suspicious activity related to the detection of known vulnerabilities or the use of unusual security recommendations.
SecurityAlert
| where ProviderName == "Azure Security Center"
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "4658" and TimeGenerated > ago(1d)
| join kind=inner SecurityEvent on CorrelationId, EventId
| where EventId == "4659" and TimeGenerated > ago(1d)

Suspicious Azure Firewall Activity: This query helps identify instances where there is suspicious activity related to Azure Firewall, such as the use of known malicious IP addresses or unusual traffic patterns.
AzureDiagnostics
| where Category == "AzureFirewallApplicationRule" and TimeGenerated > ago(1d)
| where RuleAction == "Deny" and DestinationIP contains "127.0.0.1" or DestinationIP contains "localhost" or DestinationIP contains "::1" or DestinationIP contains "fe80" or DestinationIP contains "169.254"
| summarize count() by RuleName

Don't let attackers compromise your Azure Firewall! This query will help you catch any suspicious activity related to the use of known malicious IP addresses or unusual traffic patterns.
AzureDiagnostics
| where Category == "AzureFirewallApplicationRule" and TimeGenerated > ago(1d)
| where RuleAction == "Deny" and DestinationIP contains "127.0.0.1" or DestinationIP contains "localhost" or DestinationIP contains "::1" or DestinationIP contains "fe80" or DestinationIP contains "169.254"
| summarize count() by RuleName

