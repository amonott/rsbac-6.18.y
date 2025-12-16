#
# File: rsbac/adf/Makefile
#
# Makefile for the Linux RSBAC Access Control Decision Facility (ADF)
#
# Author and (c) 1999-2020 Amon Ott <ao@rsbac.org>
#

obj-y   := adf_main.o

ifeq ($(CONFIG_RSBAC_DEBUG),y)
obj-y   += adf_check.o
endif

# Adding policies
subdir-$(CONFIG_RSBAC_MAC) += mac
obj-$(CONFIG_RSBAC_MAC) += mac/

subdir-$(CONFIG_RSBAC_FF) += ff
obj-$(CONFIG_RSBAC_FF) += ff/

subdir-$(CONFIG_RSBAC_RC) += rc
obj-$(CONFIG_RSBAC_RC) += rc/

subdir-$(CONFIG_RSBAC_AUTH) += auth
obj-$(CONFIG_RSBAC_AUTH) += auth/

subdir-$(CONFIG_RSBAC_ACL) += acl
obj-$(CONFIG_RSBAC_ACL) += acl/

subdir-$(CONFIG_RSBAC_CAP) += cap
obj-$(CONFIG_RSBAC_CAP) += cap/

subdir-$(CONFIG_RSBAC_JAIL) += jail
obj-$(CONFIG_RSBAC_JAIL) += jail/

subdir-$(CONFIG_RSBAC_RES) += res
obj-$(CONFIG_RSBAC_RES) += res/

subdir-$(CONFIG_RSBAC_UDF) += udf
obj-$(CONFIG_RSBAC_UDF) += udf/

subdir-$(CONFIG_RSBAC_REG) += reg
obj-$(CONFIG_RSBAC_REG) += reg/
ifeq ($(CONFIG_RSBAC_REG_SAMPLES),y)
subdir-m += reg
endif

