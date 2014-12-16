TARGET=ricks_netfpga_dns
 include ../bench.mk
 ricks_netfpga_dns: ricks_netfpga_dns.c my_inet.c my_inet.h triez_netfpga.c triez_netfpga.h structs_netfpga.h shared_functions_netfpga.c shared_functions_netfpga.h dns_netfpga.h  ricks_netfpga_dns.o pktbuff.o memcpy.o
 #ricks_netfpga_dns: ricks_netfpga_dns.c my_inet.c my_inet.h triez_netfpga.c triez_netfpga.h structs_netfpga.h shared_functions_netfpga.c shared_functions_netfpga.h dns_netfpga.h  ricks_netfpga_dns.o pktbuff.o memcpy.o
 #ricks_netfpga_dns: ricks_netfpga_dns.c triez_netfpga.h structs_netfpga.h shared_functions_netfpga.h dns_netfpga.h ricks_netfpga_dns.o pktbuff.o memcpy.o
#UDEFINCS ?= -I. -I../common -I/usr/include
