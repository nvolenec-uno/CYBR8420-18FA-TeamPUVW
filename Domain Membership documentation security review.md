Review of Samba User documentation – https://wiki.samba.org/index.php/User_Documentation
Domain Membership section

Section1 – Joining a Windows Client or Server to a Domain
	Introduction – no changes found for this section
	System Requirements
	Supported Windows Versions
		The Windows 10 Wiki : https://en.wikipedia.org/wiki/Windows_10_version_history
		Lists several subversions for Windows 10 support which are not listed in the current Samba documentation. 
		There are four versions listed Home and Pro, Enterprise – Education, Enterprise – LTSB, and Mobile.  
		The Samba.org site lists Pro, Enterprise and Education.
		Samba.org does not list Windows Server 2019 which became available in March 2018.
		Permissions: there is a possible typo in ”Note, that in an AD authenticated”
		Can add a reference for the ten user machines to join a AD domain:
			https://support.microsoft.com/en-us/help/243327/default-limit-to-number-of-workstations-a-user-can-join-to-the-domain
		In Date and Time settings (AD Only), the footnote for maximum tolerance for computer clock synchronization is obsolete. 
			The new reference footnote should be to this Windows 10 site:
			https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization
			It remains a default of 5 minutes but this link also includes Group Policy Objects.
			This section could be improved by adding a reference to NetBIOS naming conventions.
			https://support.microsoft.com/en-us/help/909264/naming-conventions-in-active-directory-for-computers-domains-sites-and
Section 2 – Joining a Linux or Unix Host to a Domain
	This section redirects to: Setting up Samba as a Domain Member
	Linux and Unix DNS Configuration – this section could be expanded with a reference to port 53 BIND protocol (TCP and UDP) to reach the DNS server.
		More details here: https://websistent.com/setup-linux-dns-server-for-windows-active-directory/
	Setting Up an Identity Mapping Backend
		This section describes how to use identity mapping with Active Directory (RFC 2307), rid,autoid, ldap and nss.
		The section https://wiki.samba.org/index.php/Configuring_Winbindd_on_a_Samba_AD_DC 
		contains a description of using winbindd daemon on Linux or Unix to map Linux or Unix ID’s to a matching Active Directory ID.
	There is one potential security issue here regarding the resolution of revoked ID’s remaining active in Active Directory.
	The section on Pluggable Authentication Modules (PAM) for Linux Samba clients should reference the Linux PAM Wiki. 
		http://www.linux-pam.org/
	The section on identity map use with ldap is incomplete: https://wiki.samba.org/index.php/Idmap_config_ldap
	The section on identity map use with name service switch (NSS) is incomplete: https://wiki.samba.org/index.php/Idmap_config_nss
	Authenticating Domain Users Using PAM (Programmable Authentication Modules)
	Microsoft has a great technical article on using PAM with Samba in the AD Domain environment here: 
		https://technet.microsoft.com/en-us/library/2008.12.linux.aspx?f=255&MSPPError=-2147217396
	Samba does not explain CUPS – the Linux to Windows print daemon.
	PAM Offline Authentication – describes a mechanism for using Samba authentication in an offline mode. 
	This section is dependent on the winbindd service using a cached login to the Samba server using ssh.
	Samba Domain Port Member Usage – Samba uses well known SMB TCP port 445. It depends on services such 
		as the DCE/RPC Locator Service (End Point Mapper) on TCP port 135, NetBIOS Name Service at UDP port 137, 
		NetBIOS Datagram at UDP port 138, and NetBIOS Session TCP port 139.
	Joining a Mac OS X Client to a Domain and Mac OS X DNS Configuration – both of these sections are currently blank 
	Configuring FreeDOS to Access a Samba Share – this section describes how to use FreeDOS operating system as a Samba client which not officially supported.
	Troubleshooting Samba Domain Members- this section defines some high level commands which can be used to isolate authentication problems and membership in an Active Directory forest.  It is missing content for Domain Members in an NT4 domain.
	
There is an overall Samba Bugzilla project including a Documentation page here: 
https://bugzilla.samba.org/describecomponents.cgi?product=Samba%204.1%20and%20newer

No one is currently listed as the Samba documentation champion


