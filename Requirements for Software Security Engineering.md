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
# Search Files
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuse case p1 - Search Files.png)  
## Misuse case notion and quality
Use of proper misuse case notation (as discussed in class). Reasoning Quality: Misuse cases reflect reasoning that help derive security requirements.

## Threat: Hide or delete content on file server /Privilege escalation/ 

In the company, HR manager and employee both access to employee’s directory on file server which contains their application. HR employee also copy job candidate’s application to same folder. 
Malicious insider who is not authorized to edit this file has granted access and hidden some of competitive candidate’s information intentionally.     

## Prevention: Setting permission 

To set permission on users individually or group. Prohibit any guest account. 

## Reflection
Assess alignment of security requirements with advertised features. Review OSS project documentation and codebase to support your observations.

Samba has multiple methods of user authentication. Feature is to check user in two level: 1. User name and password 2. Access rights to the files and directories. 

Samba can handle individual users, guest users and groups share access by using its flags in configuration file. For example:

path = /home/dave</br>
comment = Dave's home directory</br>
writable = yes</br>
valid users = dave</br>

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

OSS project documentation review
Review OSS project documentation for security-related configuration and installation issues. Summarize your observations.

Samba had an authentication related issue which allows NTLMv1 on SMB1 transport, even if disabled on the server side. It has been disabled since Samba version 4.5, but was reintroduced in version 4.7 which caused the error occurrence again. Version 4.8.3 fixed this error on 14th of August, 2018. 

CVE-2018-1139 (Weak authentication protocol allowed.)

https://www.samba.org/samba/history/

<li>Print Jobs</li>
<li>List of Files</li>
</ol>

# Misuse cases for listing of files on the SAMBA server:

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
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuse case p1 - List of Files.png)

# Misuse cases for E-mail Links to Files

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

![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/misuse case p1 - Email Links to Files.png)
