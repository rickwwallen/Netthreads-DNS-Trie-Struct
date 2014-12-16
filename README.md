Netthreads-DNS-Trie-Struct
==========================

NetThreads dependent version of the RWW-TRIE_STRUCT_DNS. Requires the NetThreads compiler project to be already loaded 
and set up. This project is to be used on the NetFPGA 1G.

This code utilizes a NetFPGA compiler project NetThreads. This compiler is required for the usage of the code in this
project. Compiling and loading the code is based upon the NetThreads project and instructions can be seen via site
https://github.com/NetFPGA/netfpga/wiki/NetThreads

Current state of the project is still under development as of December 15, 2014 and may not work. The project does not 
compile, though the code is in a state for testing.

Directory name and files:
../ricks_netfpga_dns/
|-- Makefile
|-- README.md
|-- dev.c
|-- dev.h
|-- dns_netfpga.h
|-- ricks_netfpga_dns.c
|-- shared_functions_netfpga.c
|-- shared_functions_netfpga.h
|-- structs_netfpga.h
|-- triez_netfpga.c
`-- triez_netfpga.h
