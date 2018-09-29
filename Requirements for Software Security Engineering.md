# Requirements for Software Security Engineering

## Essential Data Flows:

### Description of the use case scenario:

The SAMBA server is a network file server for a small company including their HR department.
The system is used to store files for office use including search and email capability using links.
The files can be shared with other employees in the company outside of the HR department.
The files can be printed using a network attached printer.
The file directories can be listed and searched.

# CRUD
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuseCase-CRUDp1.jpeg)
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuseCase-CRUDp2.jpeg)
# Search Contents of Files
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misusecasep1-SearchFiles.png)  

## Description of misuse case scenario:

In the company, HR manager and employee both access to employee’s directory on file server which contains their application. HR employee also copy job candidate’s application to same folder. 
Malicious insider who is not authorized to edit this file has granted access and hidden some of competitive candidate’s information intentionally.     

### Threat: Hide or delete content on file server /Privilege escalation/, DoS /Buffer overflow/
### Mitigation: Setting permission 
### Prevention: Prohibit guest account

To set permission on users individually or group. Prohibit any guest account. 

- Samba has multiple methods of user authentication. Feature is to check user in two level: 
1. User name and password 
2. Access rights to the files and directories. 

Samba can handle individual users, guest users and groups share access by using its flags in configuration file. For example:

path = /home/dave  
comment = Dave's home directory  
writable = yes  
valid users = dave   

Share-level access options

| Options 	| Parameters 	| Function 	| Default 	| On scope 	|
| ---------	| ----------- | --------- | --------- | --------- |
| admin users 	| string (list of usernames) 	| Users who can perform operations as root 	| None 	| Share 	|
| valid users 	| string (list of usernames) 	| Users who can connect to a share 	| None 	| Share 	|
| invalid users 	| string (list of usernames) 	| Users who will be denied access to a share 	| None 	| Share 	|
| read list 	| string (list of usernames) 	| Users who have read-only access to a writable share 	| None 	| Share 	|
| write list 	| string (list of usernames) 	| Users who have read/write access to a read-only share 	| None 	| Share 	|
| max connections 	| numeric 	| Maximum number of connections for a share at a given time 	| 0 	| Share 	|
| guest only (only guest) 	| Boolean 	| If yes, allows only guest access 	| No 	| Share 	|
| guest account 	| string (name of account) 	| Unix account that will be used for guest access 	| Nobody 	| Share 	|

https://www.samba.org/samba/docs/using_samba/ch09.html

- Samba had bufferoverflow issue on older versions /2.2.x/. CVE-2003-0201 

## OSS Documentation review:

-Missing security configs: Firewall configuration during installation Samba. 

If there is a firewall, 137-139,445 ports must be open. 

https://wiki.archlinux.org/index.php/samba#Configure_Firewall

# Listing of files 
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuseCasep1-ListofFiles.png)
## Misuse cases for listing of files on a Samba server
1. Path or Directory Traversal - this misuse case is when a file path or directory
   is misconfigured or terminates file name access due to an error. This causes the
   HR manager or employees to not be able to list files on the server. One example
   in the code base was when a man in the middle attack allowed read and alter
   access via a client connection when a DFS (file server) redirect when the
   original connection was SMB3. 
   (https://www.samba.org/samba/security/CVE-2017-12151.html)

2. Exploit Sensitive Files - this misuse case occurs when sensitive files are
   inadvertently exposed to the HR manager or other employees on the server. An
   example would be a document of employees to be terminated or laid off.
   (https://www.samba.org/samba/security/CVE-2018-10919.html)

3. Corrupted directories or file names - this misuse case occurs when the file
   names or directories contain non-displayed or malformed file names, such as
   binary file names, causing the HR manager not to be able to access the files
   or delete or modify the file names. This was demonstrated as a August 2018
   security error in SAMBA. (https://www.samba.org/samba/security/CVE-2018-10858.html)
   
#### Threat: Directory or Path Traversal, Exploit Sensitive Files, Corrupted File Names or Directories
#### Mitigation: Run file system checks on corrupted files/Samba backups
https://www.samba.org/samba/docs/using_samba/ch05.html
#### Prevention: Strong authentication and access control list enforcement

# E-mail links to files
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuseCasep1-EmailLinkstoFiles.png)
## Misuse cases for e-mail links to files on a Samba server

1. Malicious file injection - this misuse case is when a link is shared with
   a malicious file which could potentially be opened by a recipient which
   would then inject malware on the HR manager or employees client computer.
   One example was a bug were a SAMBA server was caused to execute from
   a writable share using a shared library.
   (https://www.samba.org/samba/security/CVE-2017-7494.html)

2. File Manipulation - this misuse case is when the email link is used to
   alter the contents or the name of a file on a server. This could also be
   used to maliciously copy or duplicate files across servers. One example
   in the code base was a time-of-check, time-of-use race condition which
   allowed clients to access non-exported parts of the file system via
   symbolic links. (https://www.samba.org/samba/security/CVE-2017-2619.html)

3. Man-in-the-Middle - this misuse case is when someone uses a file link
   accessed from a network monitor like Wireshark or a email interceptor program
   to steal information from the email or the file server. For example, one
   email could contain a link to a file and other emails could contain a user
   id and password to access the file. See Man-in-the-Middle attack patch
   (https://www.samba.org/samba/security/CVE-2017-12150.html)
   
#### Threat: Malicious file injection, File Manipulation and Man-in-the-Middle attack
#### Mitigation: Use Samba Access Control List (ACL) of files for fine grained control
https://wiki.samba.org/index.php/Setting_up_a_Share_Using_Windows_ACLs
#### Prevention: Strong authentication and access control list enforcement

### Alignment of security requirements

User Authentication - Samba requires that users be authenticated through one of several possible
external authentication services including Active Directory, LDAP or pluggable authentication modules.
After authentication the Samba client uses a CID to ensure the identity of each user is verfied on 
the server message block protocol.

Audit Log - Samba supports anaudit log for Samba client access. This log can be extensively configured
to monitor discrete events for every typeoffile access event including listing of files.
https://wiki.samba.org/index.php/Setting_up_Audit_Logging

### OSS Documentation Review

A careful review of the Samba documentation Wiki found several opportunities for missing or 
incomplete documentation. Though no specific security related items were found in the documentation
there are numerous technical errors which were discovered. For example the documentation has
not been updated tp the current Windows 10 clients.
	
There is an overall Samba Bugzilla project including a Documentation page here: 
https://bugzilla.samba.org/describecomponents.cgi?product=Samba%204.1%20and%20newer

No one is currently listed as the Samba documentation champion

# Print Files
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/printjobs.png)
## Misuse cases for printing files on a SAMBA server.

1. Treekiller joe wants to spam print jobs to printers to prevent actual jobs from being printed.  He can do
   this in samba with multiple methods.  The first method is to send a large number of print jobs such that no one is
   able to create new print jobs.  The second method is to send overly large prints as to make print jobs take an overly
   large amount of time preventing access to the printer.

2. The Disruptor tom wants to cause as much harm as possible by interfering with print jobs by altering the print
   and forcing canceled jobs.  This could be done by sending or stopping signals to printers.

3. Sells Data for Cash josh wants to steal information about the prints by eavesdropping on the network.
   He can do this by monitoring the SMB files that are transfered.  The default in samba is to not encrypt SMB files
   and if the configurations are not set the files are easily eavesdropped on.

## Alignment of Security Requirements

1. User Authorization - Samba supports user authorization with user permissions to control access as well as
   user authorization with active directory, and this prevents malicous users from altering print jobs or stoping 
   print stop signals from being transfered.

2. Printer Settings to Limit Jobs - Yes, samba does have the ability to limit the size of prints
   documented here:  https://www.samba.org/samba/docs/old/Samba3-HOWTO/CUPS-printing.html.  
   This functionality is only available if the samba server back end is setup as a CUPS print server.

3. Encrypt Files - Yes samba does allow you to encrypt print files:  
   https://www.linuxjournal.com/content/smbclient-security-windows-printing-and-file-transfer.  
   Print files are SMB files so the files must be encrypted as such, and the way to do this in samba is not very powerful.

## OSS project documentation review.

As the domain controls in samba are widely used the documentation on setup is very thorough
with Active directory, but with the less used NT4 domain controller the documentation is much
sparser with setting up samba as an NT4 BDC being completly empty.  This leaves some area to add
some setup documentation in the user documentation.

Within Joining a Windows Server 2012 / 2012 R2 DC to a Samba AD there are currently warnings about adding a Windows 2012 server
to a samba active directory.  This can be indicative of an issue with adding a Windows Server 2008 server as well, and testing 
could show that a warning needs to be added to Joining a Windows Server 2008 / 2008 R2 DC to a Samba AD as well or if the issue
is not present on the Windows Server 2008 a note the bug does not affect Windows Server 2008.


# Project Board
Link to GitHub repository that shows internal project task assignments and collaborations.
https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/projects/1
