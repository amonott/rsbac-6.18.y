#
# Makefile for the Rule Set Based Access Control helpers.
#
# Author and (c) 1999-2012 Amon Ott <ao@rsbac.org>
obj-y := syscalls.o helpers.o getname.o debug.o rkmem.o net_getname.o
#lsm.o

obj-$(CONFIG_RSBAC_RC) += rc_getname.o
obj-$(CONFIG_RSBAC_ACL) += acl_getname.o
obj-$(CONFIG_RSBAC_RES) += res_getname.o
obj-$(CONFIG_RSBAC_CAP_LOG_MISSING) += cap_getname.o
obj-$(CONFIG_RSBAC_JAIL_LOG_MISSING) += jail_getname.o
obj-$(CONFIG_RSBAC_NET_OBJ) += net_helpers.o
