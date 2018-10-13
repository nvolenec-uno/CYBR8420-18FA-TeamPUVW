# Assurance Cases

## Goal Structuring Notation and Assurance Cases:

The purpose of this document is construct five assurance claims regarding the security aspects of the
Samba file server, which is our open source project of choice. Assurance claims are: **"reasoned and compelling
arguments, which are supported by a body of evidence, that a system, service or organization will operate as
intended for a defined application in a defined environment."**<sup>1</sup>

### Description of the open source use case scenario:

The SAMBA server is a network file server for a small company including their HR department.
The system is used to store files for office use including search and email capability using links.
The files can be shared with other employees in the company outside of the HR department.
The files can be printed using a network attached printer.
The file directories can be listed and searched.

### Assurance Claims

We examined the following assurance cases for this document:

| Number    | Description   | Section   |
|:-------:|:------:|:-----:|
| 1. | Samba is protected from authentication protection | (Authentication) |
| 2. | Samba is protected from privilege escalation | (Privilege Escalation) |
| 3. | Samba is protected from session hijacking | (Session Hijacking) |
| 4. | Samba is protected from malicious code injection | (Code Injection) |
| 5. | Samba is protected during secure recovery | (Server Recovery) |

# Authentication
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/authentication.png)

## Explanation of claims and evidence:


Evidence 3.1:

This document shows the SMB authentication exchange process:
Samba implements the robust SMB authentication process wherein there are multiple exchanges between
the server and client to establish a client's session.

https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB/[MS-SMB].pdf  page 135



Evidence 4.1:

This document shows Samba's mechanism for setting an account policy like "bad lockout attempt"
which dictates how many failed login attempts are allowed before a user's account is locked.

https://www.samba.org/samba/docs/current/man-html/pdbedit.8.html section on "--value account-policy-value" option


Evidence 5.1:

This document shows how to enable Samba's strongest hashing algorithm for the
storage of user passwords running pbedit with the "--set-nt-hash" argument will
enable NT hashing for password storage.

https://www.samba.org/samba/docs/current/man-html/pdbedit.8.html  section on: "--set-nt-hash" option



Evidence 6.1:
This document shows Samba's configuration file setting for turning on network encryption.
Setting smb encrypt to "required" will turn on and force the use of network encryption.

https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#SMBENCRYPT



Evidence 7.1:

This document shows Samba's configuration file setting the session inactivty timeout
Setting "deadtime = 15" will enforce a timeout of 15 minutes for inactive sessions.

https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#DEADTIME


# Privilege Escalation
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/privilegeescalation.png)  
## Privilege Escalation

### Evidence 3.1: Scripting language esclation with XSS controls

The default configurationof Samba does not include the scripting language interface
used in the Samba Web Authentication tool by default.
https://www.samba.org/samba/security/CVE-2013-0214.html

### Evidence 3.2: DNS resolution required for XSS attacks

Samba requires a DNS server be administered as part of the Active Directory integration.
https://wiki.samba.org/index.php/DNS_Administration  
Samba patched an internal error with DNS server resolution in Samba 4.
https://lists.samba.org/archive/samba/2014-August/184458.html

### Evidence 4.1: Operating System Executable privilege protection
SambaCry was a remote code execution CVE which Samba famously has patched.
https://thehackernews.com/2017/05/samba-rce-exploit.html

### Evidence 4.2: Samba libraries have external controls

Samba had a CVE which was repaired that allowed external libraries to be uploaded and
called by the server to execute it. This security patch was identified by:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494

### Evidence 5.1: Server Message Block requests

Microsoft had a previous CVE which was repaired that allowed external SMB protocol 
requests to execute a denial of service attack on Samba.
https://www.secureworks.com/blog/attacking-windows-smb-zero-day-vulnerability
## Explanation of claims and evidence:
# Session Hijacking
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/sessionhijacking.png)
## Explanation of claims and evidence:

### Evidence 3.1: 
Samba has a security feature to encrypt network connection. 
smb encrypt = auto [global] in smb.conf file. 

Test: Tested by wireshark capture on TCP stream, port 445.

https://serverfault.com/questions/657942/encrypting-smb-traffic-with-samba

### Evidence 4.1: 
The pdbedit tool uses the passdb modular interface and is independent from the kind of users database used (currently there are smbpasswd, ldap, nis+ and tdb based and more can be added without changing the tool).
There are five main ways to use pdbedit: adding a user account, removing a user account, modifying a user account, listing user accounts, importing users accounts.

https://www.samba.org/samba/docs/current/man-html/pdbedit.8.html

### Evidence 6.1: 
Samba can handle its users access by group and individually. Also there is an option for guest user who does not have user name and password. 

https://www.samba.org/samba/docs/using_samba/ch09.html 

### Evidence 7.1: 
Samba can disable inactive sessions by configuring on smb.conf file - global config. deadtime=10 -> (10 minutes after, session will be disabled). Keepalive configuration is intended to set wait time between "Netbios keepalive packets". Keepalive packets are used to ping a client to make sure connection still alive.  

Test plan: to connect remotehost and lock pc for 10 minutes. Check on server side "smbstatus -b"

### Evidence 8.1: 
Every access with authentication checked against PAM library. PAM can be configured to check users authentication. pam_access delivers log-daemon-style login access control using login/domain names depending on pre-defined rules in /etc/security/access.conf

https://www.ibm.com/developerworks/library/l-pam/index.html

Test plan: To configure Domain control, and disable one user. After that, trying to connect to Samba share by using disabled user's credentials. 

### Evidence 9.1: 
Every access with authentication checked against PAM library /pam.security.so/ 
pam_securetty.so module checks to see that the requested user is allowed to log in at the console in question by comparing the user's login location against the /etc/securetty file. This action is required; if it fails, the authentication request will be rejected after all other actions have been completed.

http://www.informit.com/articles/article.aspx?p=20968&seqNum=3

### Evidence 10.1: 
Samba security mechanism can authenticate users by configuring on smb.conf file.

https://www.samba.org/samba/docs/using_samba/ch09.html 



# Code Injection
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/codeinjection.png)
## Explanation of claims and evidence:

### Evidence 3.1
Because of linux, only users with execute permissions are allowed to execute files on a samba share.

https://wiki.samba.org/index.php/Setting_up_a_Share_Using_POSIX_ACLs
https://www.samba.org/samba/docs/using_samba/ch08.html
### Evidence 4.1
The Samba bug tracker shows that if there are any buffer overflow errors that they get fixed or resolved in a timely manner.

https://bugzilla.samba.org/buglist.cgi?bug_status=__all__&content=Buffer%20Overflow&no_redirect=1&order=Importance&product=&query_format=specific
### Evidence 6.1
The samba documentation shows that the Samba Web administration tool is not installed or enabled by default.

https://www.samba.org/samba/docs/4.0/man-html/swat.8.html
## Evidence 8.1
On linux ony users can execute files and on our implementation there  is no user for samba to
manipulate files as.  Thus, Samba connection scripts can not execute files.

https://www.samba.org/samba/docs/using_samba/ch08.html

# Server Recovery
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/securerecovery.png)
## Explanation of claims and evidence:



# Project Board
Link to GitHub repository that shows internal project task assignments and collaborations.  
https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/projects/1

<sup>1</sup>Goal Structuring Notation Community Standard, Version 2, SCSC-141B
https://scsc.uk/r141B:1?t=1
