# University of Nebraska Omaha

# CYBR 8420 Software Assurance

### Assignment: Designing for Software Security Engineering
### November 7, 2018

## Team PUVW members:

### Chinguun Purevdagva <cpurevdagva@unomaha.edu>

### Jackson Urrutia <jurrutia@unomaha.edu>

### Nick Volenec <nvolenec@unomaha.edu>

### Bob Wilmes <rwilmes@unomaha.edu>


### Level 0 DFDs

  ![CRUD DFD0](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/crud_dfd_level_0.PNG)
  ![email DFD0](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/email_dfd_level_0.PNG)
  ![print DFD0](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/print_dfd_level_0.PNG)
  ![search DFD0](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/Notes/search_dfd_level_0.PNG)
  ![list DFD0](https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/Notes/list_dfd_level_0.PNG)

### Level 1 DFD

   <https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/Samba_Level_1.htm>

   As a pdf <https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/blob/master/include/Samba_Level_1.pdf>


### Summary of Samba software design for STRIDE threats identified in DFD

  In general Samba has fairly robust mitigation for the identified STRIDE threats.  Samba is generally secure from spoofing due to
authentication controls and the fact that Samba runs on a restricted port and hence protected by operating system controls.  Samba is
generally secure from tampering due to authentication provided by the SMB protocol that Samba implements.  Samba is generally secure from
repudiation because it can be run with robust logging enabled.  Since Samba can be configured to use encryption for all communications
it is generally protected from information disclosure vulnerabilities.  Samba can be configured to run in a multi-server environment
which can provide denial of service protection.  Samba is protected from elevation of privilege exploits due to a combination of
operating system controls and SMB protocol features.



Project Board
Link to GitHub repository that shows internal project task assignments and collaborations.
https://github.com/nvolenec-uno/CYBR8420-18FA-TeamPUVW/projects/4
