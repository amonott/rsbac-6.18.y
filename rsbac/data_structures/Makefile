#
# File: rsbac/data_structures/Makefile
#
# Makefile for the RSBAC data structures.
#
# Author and (c) 1999-2012 Amon Ott <ao@rsbac.org>
#

obj-y += aci_data_structures.o gen_lists.o

# Adding policy dependent data structures

obj-$(CONFIG_RSBAC_MAC) += mac_data_structures.o
obj-$(CONFIG_RSBAC_RC) += rc_data_structures.o
obj-$(CONFIG_RSBAC_AUTH) += auth_data_structures.o
obj-$(CONFIG_RSBAC_ACL) += acl_data_structures.o
obj-$(CONFIG_RSBAC_UM) += um_data_structures.o

