[![bekhterev.me](https://img.shields.io/badge/bekhterev.me-some%20kind%20of%20blog-green.svg)](https://bekhterev.me)

backupy
========

**backupy** backups files using Paramiko SSH. It has options to backup Mikrotik RouterOS configuration and files. It is currently in alfa stage.

Features
------------

- Get RouterOS cfg
- Copy remote RouterOS files
- Copy remote pfSense/linux files
- Deploy SSH key to RouterOS device (TODO yet)
- Deploy SSH key to Linux device
- Delete duplicate files
- Run remote ssh command


Quick Start
-----------

Need to write all that stuff.

CLI Usage Example
-----------------
:
Need to write all that stuff.

Known Issues
------------

- when a lot of files are copied error occurs: "paramiko.ssh_exception.ChannelException: (1, 'Administratively prohibited')"
- ftp get need to me modified to copy to /target/ not to /target/ip/ folder
- if -i arg ip validation failed, additional empty string returned
- with --multi arg output is totally mixed 


Recent Changes
--------------
0.1.1

- multiprocessing broke -i --ip args processing for other then --ros modes - FIXED
- --overwrite arg added, by default it will not copy file if its same size as local
- some small fixes


0.1.0 

- multithreading added
- argument parsing added
- script mode and interactive mode switch (show progress or not), switch with -v or --verbose 
- check if key alredy added (but only for self, if you want to deploy other hosts` key, check will not work)


0.0.1 

- separate repository created

TODO:
--------------
- do not create empty folders if wildmask is used
- enhance show progress for file transferring
- keys deployment for RouterOS devices
- logging for script mode and per host
- pfSense backup function (added with simple options)
- MySQL backup function
- remote CMD from args