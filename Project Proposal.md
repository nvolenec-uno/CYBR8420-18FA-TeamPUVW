University of Nebraska Omaha

CYBR 8420 Software Assurance

September 3, 2018

Team PUVW members:

Chinguun Purevdagva <cpurevdagva@unomaha.edu>

Jackson Urrutia <jurrutia@unomaha.edu>

Nick Volenec <nvolenec@unomaha.edu>

Bob Wilmes <rwilmes@unomaha.edu>

Open Source project: <http://www.samba.org> or <https://git.samba.org>

Overview: SAMBA is an open source implementation of a network file server which
implements the SMB (Server Module Block) and CIFS (Common Internet File System)
network server for file and print services. SAMBA supports a number of Microsoft
Windows clients typically connected by SMB/CIFS network protocols to a server
running on Unix, OpenVMS, and Unix-like systems such as Linux, Solaris, AIX and
BSD variants such as the macOS Server and macOS client. SAMBA integrates with
Microsoft Windows Domain Server, Active Directory and Windows Domain
controllers.

SAMBA was originally developed by Andrew Tridgell. Currently SAMBA is maintained by "the samba team" a group of 54 people from all over the world.

The current stable release of SAMBA is 4.8.5 (September 10, 2018).

-   What are the security needs of users from this software in its intended
    threat environment (e.g., home, office, enterprise, bank, government, etc.)?
    If there are none or very few, then re-evaluate your selection.

>   Typically, SAMBA is used when many employees, students, or staff members
>   share access to Windows based files such as spreadsheets, word documents,
>   Adobe PDF documents which are used in business or office practices. Many
>   organizations rely on Microsoft Active Directory server to perform
>   authentication and authorizations for file system users. There is oftentimes
>   a security threat created by misconfiguration or a lack of security patches
>   being applied to a working server. Users also need to understand that
>   confidential information maybe included in print images served by Samba to
>   network printers.

-   Develop a list of security features in the software. Again, if there are
    none or very few, then re-evaluate your choice.

>   SAMBA needs to provide security features in the following areas:

1.  Authentication of users and administrators

2.  Authorization of users and administrators for file processing and printing

3.  Auditing and logging of file access and print logs for users and
    administrators

4.  Hardening of network security protocols and services exposed by the SAMBA
    server

5.  Resistant to script based attacks on the user interfaces.

-   Motivation for selecting this project

>   SAMBA is a large, mature open source project which is widely used. It has
>   many modules and security components which are maintained by a large
>   contributor base. SAMBA by its nature has a large extensive security
>   exposure for potential errors. SAMBA has an open policy on accepting
>   contributions. SAMBA supports global languages and international file names.

-   Open source project description (What is it?, Contributors, Activity, Use,
    Popularity, Languages used, platform, documentation sources, etc.)

>   SAMBA is written in primarily in the C programming language and is licensed
>   under the GNU General Public License version 3 or later (as published by the
>   Free Software Foundation). SAMBA is integrated with the automated testing
>   project Travis CI (<https://travis-ci.org/>).

>   The official Git repository of the SAMBA project is
>   <https://git.samba.org/samba.git> has had 113,433 commits, 36 branches, 800
>   releases and 249 contributors as of September 2018.

-   [Discuss License, procedures for making contributions, and contributor
    agreements (Links to an external site.)Links to an external
    site.](https://opensource.guide/how-to-contribute/#orienting-yourself-to-a-new-project)

>   The GNU General Public License Version 3 is described here:
>   <https://www.gnu.org/licenses/gpl-3.0.en.html>

>   The SAMBA development process is described here:
>   <https://www.samba.org/samba/devel/>

>   SAMBA includes an Important disclaimer:

>   **Important:** In order to avoid any potential licensing issues we require
>   that anyone who has signed the [Microsoft CIFS Royalty Free
>   Agreement](http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cifs/protocol/royalty-free_cifs_technical_reference_license_agreement.asp) not
>   submit patches to Samba, nor base patches on the referenced specification.
>   We require, too, that patches submitted to Samba not infringe on any known
>   patents. Finally, as with all GPL work, the submitter should ensure that
>   submitted patches do not conflict with any third-party copyright.

-   Summary of security-related history (E.g., known vulnerabilities,
    security-related engineering decisions, security feature additions/removal,
    etc. )

>   SAMBA has a large bug database maintained at: <https://bugzilla.samba.org/>

>   The Bugzilla database lists 398 security related patches, the last one
>   \#10656 (<https://bugzilla.samba.org/show_bug.cgi?id=10656>) was modified on
>   March 2018.

The CVE database at Mitre Corporation
(<http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=samba>) lists 167 CVE entries
for SAMBA as of September 2018.

-   Link to your team GitHub repository that shows your internal project task
    assignments and collaborations to finish this task.

>   Project PUVW maintains a Github repository here:

>   <https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW>

>    Project task board is on github projects section here:

>   <https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/projects>

Team collaboration:
    This project proposal was composed, nearly entirely, in two group sessions on Saturday 9/8/2018 and Monday 9/17/2018, all team members were present for both sessions.

