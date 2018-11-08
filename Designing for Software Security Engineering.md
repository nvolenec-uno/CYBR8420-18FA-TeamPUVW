Level 0 DFDs
  ![CRUD DFD0](CYBR8420-18FA-TeamPUVW/include/crud_dfd_level_0.PNG)
  ![email DFD0](CYBR8420-18FA-TeamPUVW/include/email_dfd_level_0.PNG)
  ![print DFD0](CYBR8420-18FA-TeamPUVW/include/print_dfd_level_0.PNG)

Level 1 DFD
   <CYBR8420-18FA-TeamPUVW/include/Samba_Level_1.htm>



Summary of Samba software design for STRIDE threats identified in DFD
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
