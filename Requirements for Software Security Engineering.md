<h1>Requirements for Software Security Engineering</h1>

<h2>Essential Data Flows:</h2>

<ol>
<li>CRUD</li>
<li>Search Files</li>
  
Misuse case notion and quality
Use of proper misuse case notation (as discussed in class). Reasoning Quality: Misuse cases reflect reasoning that help derive security requirements.

Threat: Hide or delete content on file server /Privilege escalation/ 

In the company, HR manager and employee both access to employee’s directory on file server which contains their application. HR employee also copy job candidate’s application to same folder. 
Malicious insider who is not authorized to edit this file has granted access and hidden some of competitive candidate’s information intentionally.     

Prevention: Setting permission 

To set permission on users individually or group. Prohibit any guest account. 

Reflection
Assess alignment of security requirements with advertised features. Review OSS project documentation and codebase to support your observations.

Samba has multiple methods of user authentication. Feature is to check user in two level: 1. User name and password 2. Access rights to the files and directories. 

Samba can handle individual users, guest users and groups share access by using its flags in configuration file. For example:

path = /home/dave</br>
comment = Dave's home directory</br>
writable = yes</br>
valid users = dave</br>

Share-level access options

| Options 	| Parameters 	| Function 	| Default 	| On scope 	|
|-------------------------	|----------------------------	|---------------------------------------
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
<li>Email Links to Files</li>
</ol>
