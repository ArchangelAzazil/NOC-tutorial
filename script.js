// This array will hold your tech issues and their resolutions.
// You can expand this with your actual data.
const tutorialData = [
    // --- Printer Problems (10 issues) ---
    {
        id: 0,
        issueTitle: "Printer Offline Status",
        issueDescription: "The printer shows 'offline' even when connected and powered on, preventing print jobs.",
        resolutionTitle: "Resolution for Printer Offline Status",
        resolutionSteps: [
            "Check physical connections (USB/Ethernet).",
            "Ensure printer is powered on and not in sleep mode.",
            "Go to 'Devices and Printers', right-click the printer, and uncheck 'Use Printer Offline'.",
            "Restart the print spooler service (services.msc).",
            "Update or reinstall printer drivers."
        ]
    },
    {
        id: 1,
        issueTitle: "Print Jobs Stuck in Queue",
        issueDescription: "Documents sent to the printer are not printing and remain in the print queue.",
        resolutionTitle: "Resolution for Print Jobs Stuck",
        resolutionSteps: [
            "Cancel all documents in the print queue.",
            "Restart the print spooler service.",
            "Restart the printer and then the computer.",
            "Check for error messages on the printer's display.",
            "Verify network connectivity to the printer."
        ]
    },
    {
        id: 2,
        issueTitle: "Printer Not Responding",
        issueDescription: "The network printer is online but not printing documents from any connected computer.",
        resolutionTitle: "Resolution for Printer Not Responding",
        resolutionSteps: [
            "Check physical connection and power.",
            "Restart the printer and print spooler service.",
            "Update printer drivers.",
            "Ensure the printer is set as default.",
            "Try printing a test page from the printer itself."
        ]
    },
    {
        id: 3,
        issueTitle: "Faded or Streaky Prints",
        issueDescription: "Printed documents have faded text, streaks, or missing colors.",
        resolutionTitle: "Resolution for Print Quality Issues",
        resolutionSteps: [
            "Check ink/toner levels and replace cartridges if low.",
            "Run the printer's head cleaning or calibration utility.",
            "Inspect print heads for clogs or damage.",
            "Use genuine ink/toner cartridges.",
            "Ensure correct paper type settings in print preferences."
        ]
    },
    {
        id: 4,
        issueTitle: "Paper Jams",
        issueDescription: "The printer frequently reports paper jams, even when no paper is visibly stuck.",
        resolutionTitle: "Resolution for Paper Jams",
        resolutionSteps: [
            "Carefully remove any jammed paper following printer instructions.",
            "Check for small pieces of torn paper inside the printer.",
            "Clean paper feed rollers with a lint-free cloth.",
            "Ensure paper is loaded correctly and not overfilled.",
            "Use recommended paper type and weight."
        ]
    },
    {
        id: 5,
        issueTitle: "Network Printer Discovery Issues",
        issueDescription: "A new network printer cannot be discovered or added to computers on the network.",
        resolutionTitle: "Resolution for Network Printer Discovery",
        resolutionSteps: [
            "Verify printer's IP address and network connectivity.",
            "Check firewall settings on client computers and network devices.",
            "Ensure printer is on the same subnet as the computers.",
            "Try adding the printer manually using its IP address.",
            "Restart the network router/switch."
        ]
    },
    {
        id: 6,
        issueTitle: "Printer Driver Installation Failure",
        issueDescription: "Unable to install printer drivers, resulting in a non-functional printer.",
        resolutionTitle: "Resolution for Driver Installation Failure",
        resolutionSteps: [
            "Download the latest drivers directly from the manufacturer's website.",
            "Run the installer as administrator.",
            "Temporarily disable antivirus/firewall during installation.",
            "Clear out old printer drivers using Print Management (printmanagement.msc).",
            "Check for Windows updates that might include necessary components."
        ]
    },
    {
        id: 7,
        issueTitle: "Printer Prints Blank Pages",
        issueDescription: "The printer feeds paper but prints nothing on it.",
        resolutionTitle: "Resolution for Blank Pages",
        resolutionSteps: [
            "Check if ink/toner cartridges are empty or improperly installed.",
            "Perform a nozzle check or print head cleaning.",
            "Ensure the correct print driver is selected.",
            "Verify the document content is not blank or white text on white background.",
            "Check for protective tapes on new cartridges."
        ]
    },
    {
        id: 8,
        issueTitle: "Slow Printing Speed",
        issueDescription: "The printer takes an unusually long time to print documents.",
        resolutionTitle: "Resolution for Slow Printing Speed",
        resolutionSteps: [
            "Reduce print quality settings (e.g., draft mode).",
            "Print in grayscale instead of color if not needed.",
            "Ensure sufficient RAM on the printer (if applicable).",
            "Check network congestion for network printers.",
            "Update printer firmware."
        ]
    },
    {
        id: 9,
        issueTitle: "Printer Not Recognized by Computer",
        issueDescription: "The computer does not detect a USB-connected printer.",
        resolutionTitle: "Resolution for Printer Not Recognized",
        resolutionSteps: [
            "Try a different USB port.",
            "Use a different USB cable.",
            "Restart both the printer and the computer.",
            "Check Device Manager for unknown devices or driver issues.",
            "Reinstall USB drivers for the computer."
        ]
    },

    // --- Active Directory Management (10 issues) ---
    {
        id: 10,
        issueTitle: "User Account Lockouts",
        issueDescription: "Users are frequently getting locked out of their Active Directory accounts.",
        resolutionTitle: "Resolution for User Account Lockouts",
        resolutionSteps: [
            "Check event logs (Security logs, Event ID 4740) on Domain Controllers to identify source.",
            "Use 'LockoutStatus.exe' or 'Account Lockout and Management Tools' to diagnose.",
            "Investigate common causes: cached credentials, mapped drives, mobile devices, scheduled tasks.",
            "Reset user password and ensure user updates it everywhere.",
            "Implement stricter lockout policies if necessary, but with caution."
        ]
    },
    {
        id: 11,
        issueTitle: "Domain Controller Replication Issues",
        issueDescription: "Active Directory changes are not replicating between Domain Controllers.",
        resolutionTitle: "Resolution for DC Replication Issues",
        resolutionSteps: [
            "Check DNS configuration for all DCs.",
            "Use `repadmin /showrepl` to check replication status.",
            "Verify network connectivity and firewall rules between DCs (RPC, LDAP, Kerberos ports).",
            "Check for time synchronization issues (Kerberos relies on accurate time).",
            "Investigate lingering objects if replication has been broken for a long time."
        ]
    },
    {
        id: 12,
        issueTitle: "DNS Resolution Problems in AD",
        issueDescription: "Clients are unable to resolve Active Directory domain names or locate Domain Controllers.",
        resolutionTitle: "Resolution for DNS in AD",
        resolutionSteps: [
            "Ensure client machines are pointing to the correct AD-integrated DNS servers.",
            "Verify SRV records are correctly registered in DNS (e.g., `_ldap._tcp.dc._msdcs.yourdomain.com`).",
            "Check DNS server event logs for errors.",
            "Perform `ipconfig /flushdns` and `ipconfig /registerdns` on clients and DCs.",
            "Restart DNS client service or DNS server service."
        ]
    },
    {
        id: 13,
        issueTitle: "Trust Relationship Failures",
        issueDescription: "A trust relationship between two domains or forests has failed, preventing resource access.",
        resolutionTitle: "Resolution for Trust Failures",
        resolutionSteps: [
            "Verify network connectivity between the domains.",
            "Check DNS resolution for both domains from each other's DCs.",
            "Use `netdom trust` command to verify and reset the trust.",
            "Ensure time synchronization between DCs in both domains.",
            "Check firewall rules allowing necessary trust-related traffic."
        ]
    },
    {
        id: 14,
        issueTitle: "SYSVOL Not Replicating (DFS-R or FRS)",
        issueDescription: "Group Policy Objects and scripts stored in SYSVOL are not replicating across Domain Controllers.",
        resolutionTitle: "Resolution for SYSVOL Replication",
        resolutionSteps: [
            "Check DFS Replication event logs for errors (Event ID 4012, 4612 for DFS-R).",
            "Verify DFS-R service is running on all DCs.",
            "Use `dfsrdiag replicationstate` to check status.",
            "Perform a non-authoritative or authoritative restore of SYSVOL if necessary (last resort).",
            "Ensure sufficient disk space on SYSVOL drive."
        ]
    },
    {
        id: 15,
        issueTitle: "Active Directory Database Corruption",
        issueDescription: "The NTDS.DIT database is suspected of corruption, leading to DC instability.",
        resolutionTitle: "Resolution for AD Database Corruption",
        resolutionSteps: [
            "Boot DC into Directory Services Restore Mode (DSRM).",
            "Use `ntdsutil` to perform an integrity check (`files` -> `integrity`).",
            "If corrupted, perform an authoritative restore from backup.",
            "If no backup, consider demoting and re-promoting the DC (if other healthy DCs exist).",
            "Ensure proper shutdown procedures for DCs to prevent future corruption."
        ]
    },
    {
        id: 16,
        issueTitle: "FSMO Role Holder Issues",
        issueDescription: "A Flexible Single Master Operations (FSMO) role holder is offline or unresponsive.",
        resolutionTitle: "Resolution for FSMO Role Issues",
        resolutionSteps: [
            "Identify current FSMO role holders using `netdom query fsmo` or `dcdiag /test:FSMORoleOwner`. ",
            "If the role holder is temporarily down, bring it back online.",
            "If permanently lost, perform a FSMO role seizure using `ntdsutil`.",
            "Ensure proper network connectivity to the FSMO role holder.",
            "Verify DNS resolution for the FSMO role holder."
        ]
    },
    {
        id: 17,
        issueTitle: "Slow Active Directory Logons",
        issueDescription: "Users experience very slow logon times when authenticating against Active Directory.",
        resolutionTitle: "Resolution for Slow AD Logons",
        resolutionSteps: [
            "Check DNS configuration on client machines (must point to AD DNS).",
            "Verify network latency to Domain Controllers.",
            "Analyze logon scripts and Group Policy processing times (using `gpresult /h`).",
            "Check DC performance (CPU, disk I/O, network).",
            "Review AV exclusions for AD files on DCs."
        ]
    },
    {
        id: 18,
        issueTitle: "Unable to Join Domain",
        issueDescription: "New computers fail to join the Active Directory domain.",
        resolutionTitle: "Resolution for Domain Join Failure",
        resolutionSteps: [
            "Verify DNS settings on the client machine (must point to AD DNS).",
            "Check network connectivity to a Domain Controller (ping, nslookup).",
            "Ensure the computer name is unique and less than 15 characters.",
            "Verify the user account attempting the join has sufficient permissions.",
            "Check firewall rules on both client and DC."
        ]
    },
    {
        id: 19,
        issueTitle: "Active Directory Schema Extension Errors",
        issueDescription: "Errors encountered when attempting to extend the Active Directory schema.",
        resolutionTitle: "Resolution for Schema Extension Errors",
        resolutionSteps: [
            "Ensure you are logged in as a Schema Admin.",
            "Verify the Schema Master FSMO role holder is online and reachable.",
            "Check event logs for specific error codes during extension.",
            "Ensure all DCs are replicating correctly before extension.",
            "Backup System State of the Schema Master before any schema changes."
        ]
    },

    // --- Group Policy Configurations (10 issues) ---
    {
        id: 20,
        issueTitle: "Group Policy Not Applying",
        issueDescription: "Changes made to Group Policy Objects (GPOs) are not being applied to client machines or users.",
        resolutionTitle: "Resolution for GPO Not Applying",
        resolutionSteps: [
            "Run `gpupdate /force` on the client machine.",
            "Check `gpresult /r` or `gpresult /h` to see applied GPOs and any errors.",
            "Verify client has network connectivity to a Domain Controller and SYSVOL.",
            "Check event logs (Application, System, Group Policy) on the client for errors.",
            "Ensure the GPO is linked to the correct OU/domain and security filtering is correct."
        ]
    },
    {
        id: 21,
        issueTitle: "Slow Group Policy Processing",
        issueDescription: "Logon times are extended due to slow Group Policy processing.",
        resolutionTitle: "Resolution for Slow GPO Processing",
        resolutionSteps: [
            "Use `gpresult /h` to identify slow-processing GPOs or extensions.",
            "Minimize the number of GPOs applied to users/computers.",
            "Avoid applying unnecessary settings within GPOs.",
            "Optimize network connectivity to Domain Controllers and SYSVOL.",
            "Check for scripts or software installations within GPOs that might be causing delays."
        ]
    },
    {
        id: 22,
        issueTitle: "GPO Replication Issues (SYSVOL)",
        issueDescription: "Group Policy Objects are not replicating correctly between Domain Controllers, leading to inconsistencies.",
        resolutionTitle: "Resolution for GPO Replication Issues",
        resolutionSteps: [
            "This is typically a SYSVOL replication issue (DFS-R or FRS). Refer to SYSVOL replication troubleshooting steps (ID 14).",
            "Verify DFS-R or FRS service status on all DCs.",
            "Check event logs for replication errors.",
            "Ensure proper network connectivity and firewall rules between DCs."
        ]
    },
    {
        id: 23,
        issueTitle: "Group Policy Management Console (GPMC) Errors",
        issueDescription: "GPMC fails to open, displays errors, or cannot retrieve GPO information.",
        resolutionTitle: "Resolution for GPMC Errors",
        resolutionSteps: [
            "Ensure you have proper permissions to manage GPOs.",
            "Verify network connectivity to Domain Controllers.",
            "Check DNS resolution for DCs.",
            "Ensure the Group Policy Management service is running.",
            "Try running GPMC from a different administrative workstation."
        ]
    },
    {
        id: 24,
        issueTitle: "Security Filtering Not Working",
        issueDescription: "A GPO is applied to an OU, but the security filtering is not correctly limiting its application.",
        resolutionTitle: "Resolution for Security Filtering",
        resolutionSteps: [
            "Ensure the 'Authenticated Users' group (or 'Domain Computers' for computer policies) has 'Read' permission on the GPO.",
            "Add the specific user/computer groups you want the GPO to apply to in the security filtering.",
            "Verify that the 'Apply Group Policy' permission is granted to the filtered groups.",
            "Check for conflicting GPOs or blocked inheritance.",
            "Run `gpresult /h` on a target machine to see which GPOs are applied and why."
        ]
    },
    {
        id: 25,
        issueTitle: "WMI Filtering Issues with GPOs",
        issueDescription: "Group Policies using WMI filters are not applying as expected.",
        resolutionTitle: "Resolution for WMI Filtering Issues",
        resolutionSteps: [
            "Verify the WMI query syntax using `wbemtest.exe`.",
            "Ensure the WMI service is running on client machines.",
            "Check client machine's event logs for WMI errors.",
            "Verify network connectivity for WMI communication.",
            "Ensure the WMI filter is linked correctly to the GPO."
        ]
    },
    {
        id: 26,
        issueTitle: "GPO Links Not Enforced or Blocked",
        issueDescription: "GPO inheritance is not behaving as expected (e.g., 'Enforced' not working, or 'Block Inheritance' not blocking).",
        resolutionTitle: "Resolution for GPO Link Behavior",
        resolutionSteps: [
            "Understand the order of GPO processing (LSDOU - Local, Site, Domain, OU).",
            "Verify the 'Enforced' status of the GPO link in GPMC.",
            "Check if 'Block Inheritance' is enabled on the OU, which overrides 'Enforced' from higher levels.",
            "Review the GPO hierarchy and links carefully.",
            "Run `gpresult /h` to analyze the effective policy."
        ]
    },
    {
        id: 27,
        issueTitle: "Software Installation GPO Failures",
        issueDescription: "Software deployed via Group Policy is not installing on client machines.",
        resolutionTitle: "Resolution for Software Installation GPO",
        resolutionSteps: [
            "Ensure the software package (.msi) is accessible via a UNC path (e.g., `\\\\domain\\share\\package.msi`).",
            "Verify read permissions for 'Authenticated Users' on the share and the MSI file.",
            "Check client event logs (Application, System) for MsiInstaller errors.",
            "Ensure the client machine has enough disk space.",
            "Verify the GPO is linked to the correct OU containing the computers."
        ]
    },
    {
        id: 28,
        issueTitle: "Folder Redirection Issues",
        issueDescription: "User folders (e.g., Documents, Desktop) are not redirecting to network shares as configured by GPO.",
        resolutionTitle: "Resolution for Folder Redirection",
        resolutionSteps: [
            "Verify the network share permissions (users need Full Control).",
            "Check NTFS permissions on the share folder (users need Modify).",
            "Ensure the GPO is linked to the correct OU containing the users.",
            "Check client event logs for Folder Redirection errors.",
            "Verify network connectivity to the file server."
        ]
    },
    {
        id: 29,
        issueTitle: "Group Policy Preferences (GPP) Not Applying",
        issueDescription: "Settings configured via Group Policy Preferences are not being applied.",
        resolutionTitle: "Resolution for GPP Not Applying",
        resolutionSteps: [
            "Ensure the 'Authenticated Users' group has 'Read' permission on the GPO.",
            "Check the 'Item-level targeting' settings within the GPP for any misconfigurations.",
            "Verify the client-side extension (CSE) for GPP is installed and up-to-date (usually via Windows Update).",
            "Check event logs on the client for GPP errors (Event ID 4098 for Drive Maps, etc.).",
            "Run `gpupdate /force` and restart the client machine."
        ]
    },

    // --- Email Management (10 issues) ---
    {
        id: 30,
        issueTitle: "Cannot Send Emails (SMTP Error)",
        issueDescription: "Users are unable to send emails, often receiving SMTP authentication or connection errors.",
        resolutionTitle: "Resolution for Cannot Send Emails",
        resolutionSteps: [
            "Verify outgoing mail server (SMTP) settings, including port (e.g., 587 for TLS/SSL) and encryption.",
            "Ensure 'My outgoing server (SMTP) requires authentication' is checked if applicable.",
            "Check firewall rules on the client machine and network for outbound SMTP traffic.",
            "Verify internet connectivity.",
            "Test sending from webmail to rule out client-side issues."
        ]
    },
    {
        id: 31,
        issueTitle: "Cannot Receive Emails (POP3/IMAP Error)",
        issueDescription: "Users are not receiving new emails, or the email client reports connection errors to the incoming server.",
        resolutionTitle: "Resolution for Cannot Receive Emails",
        resolutionSteps: [
            "Verify incoming mail server (POP3/IMAP) settings, including port (e.g., 993 for IMAPS, 995 for POP3S) and encryption.",
            "Check firewall rules on the client machine and network for inbound POP3/IMAP traffic.",
            "Verify internet connectivity.",
            "Check mailbox storage limits.",
            "Log in to webmail to confirm emails are arriving at the server."
        ]
    },
    {
        id: 32,
        issueTitle: "Email Client Crashing/Freezing",
        issueDescription: "Outlook, Thunderbird, or other email clients frequently crash or become unresponsive.",
        resolutionTitle: "Resolution for Email Client Crashing",
        resolutionSteps: [
            "Start the email client in safe mode (e.g., `outlook.exe /safe`).",
            "Disable problematic add-ins or extensions.",
            "Repair or recreate the email profile.",
            "Run a repair installation of the email client.",
            "Ensure sufficient system resources (RAM, CPU) and disk space."
        ]
    },
    {
        id: 33,
        issueTitle: "Outlook OST/PST File Corruption",
        issueDescription: "Outlook data files (.ost or .pst) are corrupted, leading to errors or data loss.",
        resolutionTitle: "Resolution for Outlook File Corruption",
        resolutionSteps: [
            "Use the Inbox Repair Tool (scanpst.exe) to repair PST files.",
            "For OST files, recreate the Outlook profile to force a re-download from the server.",
            "Ensure Outlook is closed properly to prevent corruption.",
            "Regularly backup PST files.",
            "Check disk for errors (chkdsk)."
        ]
    },
    {
        id: 34,
        issueTitle: "Spam Filter Over-Blocking Legitimate Emails",
        issueDescription: "Important emails are being incorrectly flagged as spam and moved to junk or quarantined.",
        resolutionTitle: "Resolution for Spam Over-Blocking",
        resolutionSteps: [
            "Add legitimate senders to the 'Safe Senders' list.",
            "Adjust spam filter sensitivity settings (if available).",
            "Review quarantined emails and release false positives.",
            "Check domain's SPF, DKIM, DMARC records for proper configuration.",
            "Report false positives to email provider/security vendor."
        ]
    },
    {
        id: 35,
        issueTitle: "Email Signature Not Displaying Correctly",
        issueDescription: "HTML email signatures appear broken, with incorrect formatting or missing images.",
        resolutionTitle: "Resolution for Email Signature Issues",
        resolutionSteps: [
            "Ensure the HTML code for the signature is valid and well-formed.",
            "Use absolute URLs for images in the signature.",
            "Test the signature across different email clients (Outlook, Gmail, Apple Mail).",
            "Avoid complex CSS or JavaScript within signatures.",
            "Recreate the signature from scratch if issues persist."
        ]
    },
    {
        id: 36,
        issueTitle: "Shared Mailbox Access Issues",
        issueDescription: "Users are unable to access or send from a shared mailbox.",
        resolutionTitle: "Resolution for Shared Mailbox Access",
        resolutionSteps: [
            "Verify user has 'Full Access' and 'Send As' or 'Send on Behalf' permissions on the shared mailbox.",
            "Ensure Auto-mapping is enabled for the user's Outlook profile.",
            "Check for any cached credentials issues.",
            "Restart Outlook and the computer.",
            "Try accessing the shared mailbox via OWA (Outlook Web App)."
        ]
    },
    {
        id: 37,
        issueTitle: "Calendar Sharing/Permissions Problems",
        issueDescription: "Users cannot view or modify shared calendars, or permissions are not applying.",
        resolutionTitle: "Resolution for Calendar Sharing",
        resolutionSteps: [
            "Verify calendar sharing permissions are correctly set for the recipient.",
            "Ensure both sender and recipient are using compatible calendar versions/clients.",
            "Check for any conflicting policies or settings.",
            "Remove and re-add calendar permissions.",
            "Clear Outlook cache or recreate profile."
        ]
    },
    {
        id: 38,
        issueTitle: "Email Delivery Delays",
        issueDescription: "Emails are taking a long time to be delivered to recipients.",
        resolutionTitle: "Resolution for Email Delivery Delays",
        resolutionSteps: [
            "Check mail server queues for backlogs.",
            "Examine email headers for delivery path and delays at each hop.",
            "Verify DNS records (MX, SPF, DKIM) are correctly configured.",
            "Check for blacklisting of the sending IP address.",
            "Monitor network bandwidth and mail server performance."
        ]
    },
    {
        id: 39,
        issueTitle: "Unable to Configure Email on Mobile Device",
        issueDescription: "Users cannot set up their corporate email account on their smartphone or tablet.",
        resolutionTitle: "Resolution for Mobile Email Setup",
        resolutionSteps: [
            "Verify correct server names, ports, and security types (SSL/TLS).",
            "Ensure the user's account is enabled for mobile access.",
            "Check for any Mobile Device Management (MDM) policies restricting setup.",
            "Try using an app-specific password if 2FA is enabled.",
            "Clear cache for the mail app or reinstall it."
        ]
    },

    // --- Firewall Issues (10 issues) ---
    {
        id: 40,
        issueTitle: "Blocked Internet Access",
        issueDescription: "Users cannot access the internet or specific websites due to firewall blocking.",
        resolutionTitle: "Resolution for Blocked Internet Access",
        resolutionSteps: [
            "Check firewall logs for denied connections (source IP, destination IP/port).",
            "Verify outbound rules allowing HTTP/HTTPS (ports 80, 443).",
            "Temporarily disable the firewall (for testing only) to confirm it's the cause.",
            "Check for web filtering or content inspection rules.",
            "Ensure DNS resolution is working and not being blocked."
        ]
    },
    {
        id: 41,
        issueTitle: "Application Connectivity Issues",
        issueDescription: "Specific applications cannot connect to their required backend services or external servers.",
        resolutionTitle: "Resolution for App Connectivity",
        resolutionSteps: [
            "Identify the application's required ports and protocols.",
            "Create specific firewall rules to allow the necessary inbound/outbound traffic.",
            "Check for stateful firewall issues (e.g., connection timeout).",
            "Test connectivity using `telnet` or `Test-NetConnection` to the specific port.",
            "Review application-specific firewall exclusions."
        ]
    },
    {
        id: 42,
        issueTitle: "VPN Connection Failures",
        issueDescription: "Users are unable to establish a VPN connection to the corporate network.",
        resolutionTitle: "Resolution for VPN Connection Failures",
        resolutionSteps: [
            "Verify VPN client configuration (server address, credentials, protocol).",
            "Check firewall rules on both client and VPN server for VPN traffic (e.g., UDP 500/4500 for IKE/NAT-T, TCP 1723 for PPTP).",
            "Ensure VPN server is reachable and running.",
            "Check for conflicting network adapters or software.",
            "Review VPN server logs for connection attempts and errors."
        ]
    },
    {
        id: 43,
        issueTitle: "Remote Desktop (RDP) Access Denied",
        issueDescription: "Unable to connect to a remote server or workstation via RDP, often due to firewall.",
        resolutionTitle: "Resolution for RDP Access Denied",
        resolutionSteps: [
            "Ensure RDP is enabled on the target machine.",
            "Verify firewall rule allowing inbound TCP port 3389 to the target.",
            "Check network security groups (NSGs) or cloud firewall rules if applicable.",
            "Ensure the user account has RDP permissions.",
            "Test connectivity using `telnet <IP> 3389`."
        ]
    },
    {
        id: 44,
        issueTitle: "Firewall Performance Degradation",
        issueDescription: "The network firewall is causing significant latency or throughput reduction.",
        resolutionTitle: "Resolution for Firewall Performance",
        resolutionSteps: [
            "Review firewall CPU, memory, and session utilization.",
            "Optimize firewall rules: consolidate rules, place most hit rules higher.",
            "Disable unnecessary features (e.g., deep packet inspection, IPS) if not critical for specific traffic.",
            "Upgrade firewall hardware or firmware.",
            "Segment network to reduce traffic passing through the main firewall."
        ]
    },
    {
        id: 45,
        issueTitle: "Firewall Logs Not Populating",
        issueDescription: "Firewall logs are empty or incomplete, making troubleshooting difficult.",
        resolutionTitle: "Resolution for Firewall Logs",
        resolutionSteps: [
            "Verify logging is enabled for the relevant firewall rules and policies.",
            "Check disk space on the firewall device or log server.",
            "Ensure NTP synchronization for accurate timestamps in logs.",
            "Verify connectivity to the syslog server or SIEM solution.",
            "Restart logging services on the firewall."
        ]
    },
    {
        id: 46,
        issueTitle: "NAT/PAT Translation Issues",
        issueDescription: "Network Address Translation (NAT) or Port Address Translation (PAT) is not working as expected, causing connectivity problems for internal hosts to external services.",
        resolutionTitle: "Resolution for NAT/PAT Issues",
        resolutionSteps: [
            "Verify NAT/PAT rules are correctly configured on the firewall.",
            "Check for conflicting NAT rules.",
            "Ensure the correct interfaces are specified for NAT translation.",
            "Use firewall's packet tracer or debug commands to see NAT/PAT in action.",
            "Check for source/destination IP mismatches in NAT rules."
        ]
    },
    {
        id: 47,
        issueTitle: "Firewall Rule Misconfiguration",
        issueDescription: "An unintended firewall rule is blocking legitimate traffic or allowing unauthorized access.",
        resolutionTitle: "Resolution for Rule Misconfiguration",
        resolutionSteps: [
            "Perform a detailed audit of firewall rules, starting from the top.",
            "Use a 'least privilege' approach when creating rules.",
            "Test rules in a staging environment before deploying to production.",
            "Implement a change management process for firewall rules.",
            "Use a firewall analyzer tool to simulate traffic flow."
        ]
    },
    {
        id: 48,
        issueTitle: "Firewall Firmware Update Failures",
        issueDescription: "Attempting to update firewall firmware results in errors or device instability.",
        resolutionTitle: "Resolution for Firmware Update Failures",
        resolutionSteps: [
            "Download firmware from the official vendor website.",
            "Ensure stable power supply during the update.",
            "Backup current configuration before updating.",
            "Follow vendor-specific update procedures carefully.",
            "Check for minimum hardware requirements for the new firmware."
        ]
    },
    {
        id: 49,
        issueTitle: "Intermittent Connectivity Issues",
        issueDescription: "Users experience sporadic network connectivity drops that are difficult to diagnose.",
        resolutionTitle: "Resolution for Intermittent Connectivity",
        resolutionSteps: [
            "Check firewall session limits and timeouts.",
            "Monitor firewall resource utilization during outages.",
            "Look for asymmetric routing issues if multiple firewalls are involved.",
            "Check for duplicate IP addresses on the network.",
            "Review firewall policy order for any rules that might be intermittently triggered."
        ]
    },
    {
        id: 50,
        issueTitle: "Compromised Email Account with Malicious Inbox Rules",
        issueDescription: "User reported receiving complaints about suspicious emails sent from their account. Investigation revealed malicious inbox rules redirecting all emails to a misspelled folder ('Inboxx'), indicating account compromise.",
        resolutionTitle: "Resolution for Email Account Compromise with Malicious Rules",
        resolutionSteps: [
            "Open PowerShell as admin and connect to Exchange Online: Connect-ExchangeOnline",
            "Investigate suspicious inbox rules: Get-InboxRule -Mailbox sample@domain.com",
            "Document findings by creating breach folder: New-Item -ItemType Directory -Path \"$env:USERPROFILE\\Documents\\breach\" -Force",
            "Export detailed rule information: Get-InboxRule -Mailbox sample@domain.com | Format-List * | Out-File \"$env:USERPROFILE\\Documents\\breach\\sample_inbox_rules_$(Get-Date -Format 'yyyyMMdd_HHmm').txt\"",
            "Get audit logs for rule creation: Search-UnifiedAuditLog -UserIds sample@domain.com -Operations \"New-InboxRule\",\"Set-InboxRule\" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | Out-File \"$env:USERPROFILE\\Documents\\breach\\sample_audit_rules_$(Get-Date -Format 'yyyyMMdd_HHmm').txt\"",
            "Check login activity: Search-UnifiedAuditLog -UserIds sample@domain.com -Operations \"UserLoggedIn\" -StartDate (Get-Date).AddDays(-14) -EndDate (Get-Date) | Out-File \"$env:USERPROFILE\\Documents\\breach\\sample_login_audit_$(Get-Date -Format 'yyyyMMdd_HHmm').txt\"",
            "Get comprehensive compromise audit: Search-UnifiedAuditLog -UserIds sample@domain.com -Operations \"MailboxLogin\",\"UserLoggedIn\",\"New-InboxRule\",\"Set-Mailbox\",\"Add-MailboxPermission\" -StartDate (Get-Date).AddDays(-60) -EndDate (Get-Date) | Out-File \"$env:USERPROFILE\\Documents\\breach\\sample_comprehensive_audit_$(Get-Date -Format 'yyyyMMdd_HHmm').txt\"",
            "Remove malicious rules: Remove-InboxRule -Mailbox sample@domain.com -Identity \"RuleName\" -Confirm:$false and Remove-InboxRule -Mailbox sample@domain.com -Identity \"RuleName1\" -Confirm:$false",
            "Verify rules are deleted: Get-InboxRule -Mailbox sample@domain.com (should return empty)",
            "Force password reset for the compromised user account",
            "Enable MFA on the user account if not already enabled",
            "Configure DMARC, DKIM, and SPF records to prevent email spoofing",
            "Disconnect from Exchange Online: Disconnect-ExchangeOnline",
            "Monitor user's mailbox for 48-72 hours for any suspicious activity"
        ]
    },


    // --- Placeholder for future expansion ---
    // You can add more issues here following the same structure.
];

document.addEventListener('DOMContentLoaded', () => {
    // Determine which page we are on (index.html or resolution.html)
    const currentPage = window.location.pathname.split('/').pop();

    if (currentPage === '' || currentPage === 'index.html') {
        // This is the home page (index.html)
        loadTechIssues();
    } else if (currentPage === 'resolution.html') {
        // This is the resolution detail page
        loadResolutionDetail();
    }
});

function loadTechIssues() {
    const issuesListDiv = document.getElementById('issues-list');
    if (!issuesListDiv) {
        console.error("Element with ID 'issues-list' not found on index.html.");
        return;
    }

    // Clear any existing placeholders
    issuesListDiv.innerHTML = '';

    tutorialData.forEach(item => {
        const issueDiv = document.createElement('div');
        issueDiv.classList.add('tutorial-item');

        // Create a link that passes the item's ID as a query parameter
        const link = document.createElement('a');
        link.href = `resolution.html?id=${item.id}`;

        const issueTitle = document.createElement('h3');
        issueTitle.textContent = item.issueTitle;

        const issueDesc = document.createElement('p');
        issueDesc.textContent = item.issueDescription;

        link.appendChild(issueTitle);
        link.appendChild(issueDesc);
        issueDiv.appendChild(link);

        issuesListDiv.appendChild(issueDiv);
    });
    console.log('Tech issues loaded on index.html.');
}

function loadResolutionDetail() {
    const params = new URLSearchParams(window.location.search);
    const issueId = parseInt(params.get('id')); // Get the ID from the URL and convert to integer

    const resolutionIssueTitle = document.getElementById('resolution-issue-title');
    const resolutionContentDiv = document.getElementById('resolution-content');
    const resolutionTitleH2 = document.getElementById('resolution-title');

    if (!resolutionIssueTitle || !resolutionContentDiv || !resolutionTitleH2) {
        console.error("Required elements not found on resolution.html.");
        return;
    }

    // Find the selected issue by ID
    const selectedIssue = tutorialData.find(item => item.id === issueId);

    if (selectedIssue) {
        resolutionIssueTitle.textContent = selectedIssue.issueTitle;
        resolutionTitleH2.textContent = selectedIssue.resolutionTitle;

        let stepsHtml = '';
        if (selectedIssue.resolutionSteps && selectedIssue.resolutionSteps.length > 0) {
            stepsHtml = '<p><strong>Steps:</strong></p><ol>';
            selectedIssue.resolutionSteps.forEach(step => {
                stepsHtml += `<li>${step}</li>`;
            });
            stepsHtml += '</ol>';
        } else {
            stepsHtml = '<p>No specific resolution steps provided for this issue yet.</p>';
        }
        resolutionContentDiv.innerHTML = stepsHtml;
        console.log(`Resolution for ID ${issueId} loaded successfully.`);
    } else {
        resolutionIssueTitle.textContent = "Issue Not Found";
        resolutionTitleH2.textContent = "Error";
        resolutionContentDiv.innerHTML = "<p>The requested tech issue resolution could not be found. Please go back to the <a href='index.html'>main issues page</a>.</p>";
        console.warn(`Resolution for ID ${issueId} not found.`);
    }
}
