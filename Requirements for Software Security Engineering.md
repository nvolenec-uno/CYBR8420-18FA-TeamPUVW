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

path = /home/dave
comment = Dave's home directory
writable = yes
valid users = dave

https://www.samba.org/samba/docs/using_samba/ch09.html 

OSS project documentation review
Review OSS project documentation for security-related configuration and installation issues. Summarize your observations.

Samba had authentication related issue which allows NTLMv1 on SMB1 transport, even in disabled on the server side. However it is disabled since Samba 4.5, version 4.7 caused error occurrence again. Version 4.8.3 fixed this error on 14th of August, 2018. 

CVE-2018-1139 (Weak authentication protocol allowed.)

https://www.samba.org/samba/history/

<li>Print Jobs</li>
<li>List of Files</li>
<li>Email Links to Files</li>
</ol>
