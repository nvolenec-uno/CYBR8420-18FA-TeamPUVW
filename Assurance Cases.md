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


# Privilege Escalation
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/privilege.png)  

## Explanation of claims and evidence:
# Session Hijacking
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/sessionhijacking.png)
## Explanation of claims and evidence:

# Code Injection
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/codeinjection.png)
## Explanation of claims and evidence:


# Server Recovery
![cve-history](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/serverrecovery.png)
## Explanation of claims and evidence:



# Project Board
Link to GitHub repository that shows internal project task assignments and collaborations.  
https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/projects/1

<sup>1</sup>Goal Structuring Notation Community Standard, Version 2, SCSC-141B
https://scsc.uk/r141B:1?t=1
