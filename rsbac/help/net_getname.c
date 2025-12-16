/*
 * net_getname.c: Getname functions for the Network
 *
 * Author and Copyright (C) 1999-2021 Amon Ott <ao@rsbac.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License as
 *      published by the Free Software Foundation, version 2.
 *
 * Last modified 04/Oct/2021.
 */

#include <rsbac/types.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#include <linux/string.h>
#include <linux/module.h>

static char net_temp_syscall_list[NTS_none + 1][19] = {
	"new_template",
	"copy_template",
	"delete_template",
	"check_id",
	"get_address",
	"get_address_family",
	"get_type",
	"get_protocol",
	"get_netdev",
	"get_ports",
	"get_name",
	"set_address",
	"set_address_family",
	"set_type",
	"set_protocol",
	"set_netdev",
	"set_ports",
	"set_name",
	"none"
};

static char net_family_list[AF_MAX + 1][19] = {
	"ANY",			/* 0 */
	"UNIX",			/* 1 Unix domain sockets */
	"INET",			/* 2 Internet IP Protocol */
	"AX25",			/* 3 Amateur Radio AX.25 */
	"IPX",			/* 4 Novell IPX */
	"APPLETALK",		/* 5 AppleTalk DDP */
	"NETROM",		/* 6 Amateur Radio NET/ROM */
	"BRIDGE",		/* 7 Multiprotocol bridge */
	"ATMPVC",		/* 8 ATM PVCs */
	"X25",			/* 9 Reserved for X.25 project */
	"INET6",		/* 10 IP version 6 */
	"ROSE",			/* 11 Amateur Radio X.25 PLP */
	"DECnet",		/* 12 Reserved for DECnet project */
	"NETBEUI",		/* 13 Reserved for 802.2LLC project */
	"SECURITY",		/* 14 Security callback pseudo AF */
	"KEY",			/* 15 PF_KEY key management API */
	"NETLINK",		/* 16 */
	"PACKET",		/* 17 Packet family */
	"ASH",			/* 18 Ash */
	"ECONET",		/* 19 Acorn Econet  */
	"ATMSVC",		/* 20 ATM SVCs */
	"(undefined)",		/* 21 */
	"SNA",			/* 22 Linux SNA Project (nutters!) */
	"IRDA",			/* 23 IRDA sockets */
	"PPPOX",		/* 24 PPPoX sockets */
	"WANPIPE",		/* 25 Wanpipe API Sockets */
	"(undefined)",		/* 26 */
	"(undefined)",		/* 27 */
	"(undefined)",		/* 28 */
	"(undefined)",		/* 29 */
	"(undefined)",		/* 30 */
	"BLUETOOTH",		/* 31 Bluetooth sockets */
	"MAX"
};

#define NETLINK_FAM_MAX 19

static char net_netlink_family_list[NETLINK_FAM_MAX + 1][15] = {
	"ROUTE",		/* 0 Routing/device hook				*/
	"UNUSED",		/* 1 Unused number				*/
	"USERSOCK",		/* 2 Reserved for user mode socket protocols 	*/
	"FIREWALL",		/* 3 Firewalling hook				*/
	"INET_DIAG",		/* 4 INET socket monitoring			*/
	"NFLOG",		/* 5 netfilter/iptables ULOG */
	"XFRM",			/* 6 ipsec */
	"SELINUX",		/* 7 SELinux event notifications */
	"ISCSI",		/* 8 Open-iSCSI */
	"AUDIT",		/* 9 auditing */
	"FIB_LOOKUP",		
	"CONNECTOR",	
	"NETFILTER",		/* 12 netfilter subsystem */
	"IP6_FW",		
	"DNRTMSG",		/* 14 DECnet routing messages */
	"KOBJECT_UEVENT",	/* 15 Kernel messages to userspace */
	"GENERIC",		
	"DM",			/* 17 (DM Events) */
	"SCSITRANSPORT",	/* 18 SCSI Transports */
	"ECRYPTFS"
};

struct proto_desc_t {
	char name[19];
	int nr;
};
#define NR_PROTO 18

static struct proto_desc_t net_protocol_list[NR_PROTO] = {
	{"ANY", 0},		/* 0 Dummy protocol for TCP */
	{"ICMP", 1},		/* Internet Control Message Protocol */
	{"IGMP", 2},		/* Internet Group Management Protocol   */
	{"IPIP", 4},		/* IPIP tunnels (older KA9Q tunnels use 94) */
	{"TCP", 6},		/* Transmission Control Protocol */
	{"EGP", 8},		/* Exterior Gateway Protocol */
	{"PUP", 12},		/* PUP protocol */
	{"UDP", 17},		/* User Datagram Protocol */
	{"IDP", 22},		/* XNS IDP protocol */
	{"RSVP", 46},		/* RSVP protocol */
	{"GRE", 47},		/* Cisco GRE tunnels (rfc 1701,1702) */
	{"IPV6", 41},		/* IPv6-in-IPv4 tunnelling */
	{"PIM", 103},		/* Protocol Independent Multicast */
	{"ESP", 50},		/* Encapsulation Security Payload protocol */
	{"AH", 51},		/* Authentication Header protocol */
	{"COMP", 108},		/* Compression Header protocol */
	{"RAW", 255},		/* Raw IP packets */
	{"MAX", RSBAC_NET_PROTO_MAX}
};

static char rsbac_net_type_list[RSBAC_NET_TYPE_MAX + 1][19] = {
	"ANY",
	"STREAM",		/* 1 stream (connection) socket */
	"DGRAM",		/* 2 datagram (conn.less) socket */
	"RAW",			/* 3 raw socket */
	"RDM",			/* 4 reliably-delivered message */
	"SEQPACKET",		/* 5 sequential packet socket */
	"(undefined)",		/* 6 */
	"(undefined)",		/* 7 */
	"(undefined)",		/* 8 */
	"(undefined)",		/* 9 */
	"PACKET",		/* 10 linux specific way of */
	/* getting packets at the dev */
	/* level.  For writing rarp and */
	/* other similar things on the */
	/* user level. */
	"MAX"
};

/*****************************************/

char *rsbac_get_net_temp_syscall_name(char *name,
				      enum rsbac_net_temp_syscall_t value)
{
	if (!name)
		return NULL;
	if (value > NTS_none)
		strcpy(name, "ERROR!");
	else
		strcpy(name, net_temp_syscall_list[value]);
	return name;
};

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_get_net_family_name);
#endif
char *rsbac_get_net_family_name(char *name, u_int value)
{
	if (!name)
		return NULL;
	if (value > AF_MAX)
		strcpy(name, "ERROR!");
	else
		strcpy(name, net_family_list[value]);
	return name;
};

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_get_net_netlink_family_name);
#endif
char *rsbac_get_net_netlink_family_name(char *name, u_int value)
{
	if (!name)
		return NULL;
	if (value == RSBAC_NET_NETLINK_PROTO_ANY)
		strcpy(name, "ANY");
	if (value > NETLINK_FAM_MAX)
		strcpy(name, "ERROR!");
	else
		strcpy(name, net_netlink_family_list[value]);
	return name;
};

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_get_net_protocol_name);
#endif
char *rsbac_get_net_protocol_name(char *name, u_int value)
{
	int i;

	if (!name)
		return NULL;
	if (value >= RSBAC_NET_PROTO_MAX)
		strcpy(name, "ERROR!");
	else {
		for (i = 0; i < NR_PROTO; i++) {
			if (net_protocol_list[i].nr == value) {
				strcpy(name, net_protocol_list[i].name);
				return name;
			}
		}
		sprintf(name, "%u", value);
	}
	return name;
};

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_get_net_type_name);
#endif
char *rsbac_get_net_type_name(char *name, u_int value)
{
	if (!name)
		return NULL;
	if (value > RSBAC_NET_TYPE_MAX)
		strcpy(name, "ERROR!");
	else
		strcpy(name, rsbac_net_type_list[value]);
	return name;
};

int rsbac_net_str_to_inet(char *str, __u32 * addr)
{
	char *end;
	__u32 s0, s1, s2, s3;

	if (!str || !addr)
		return -RSBAC_EINVALIDPOINTER;
	end = str;
	while (*end) {
		if ((*end != '.')
		    && (*end != '\n')
		    && (*end != ' ')
		    && ((*end < '0')
			|| (*end > '9')
		    )
		    )
			return -RSBAC_EINVALIDVALUE;
		end++;
	}
	s0 = simple_strtoul(str, &end, 10);
	if (!*end || (s0 > 255))
		return -RSBAC_EINVALIDVALUE;
	end++;
	s1 = simple_strtoul(end, &end, 10);
	if (!*end || (s1 > 255))
		return -RSBAC_EINVALIDVALUE;
	end++;
	s2 = simple_strtoul(end, &end, 10);
	if (!*end || (s2 > 255))
		return -RSBAC_EINVALIDVALUE;
	end++;
	s3 = simple_strtoul(end, &end, 10);
	if (*end || (s3 > 255))
		return -RSBAC_EINVALIDVALUE;
	*addr = s3 | (s2 << 8) | (s1 << 16) | (s0 << 24);
	*addr = htonl(*addr);
	return 0;
}

char * rsbac_net_inet6_to_str(char * string, void * inet6)
{
	sprintf(string, "%x%02x:%x%02x:%x%02x:%x%02x:%x%02x:%x%02x:%x%02x:%x%02x",
		((__u8 *) inet6)[0],
		((__u8 *) inet6)[1],
		((__u8 *) inet6)[2],
		((__u8 *) inet6)[3],
		((__u8 *) inet6)[4],
		((__u8 *) inet6)[5],
		((__u8 *) inet6)[6],
		((__u8 *) inet6)[7],
		((__u8 *) inet6)[8],
		((__u8 *) inet6)[9],
		((__u8 *) inet6)[10],
		((__u8 *) inet6)[11],
		((__u8 *) inet6)[12],
		((__u8 *) inet6)[13],
		((__u8 *) inet6)[14],
		((__u8 *) inet6)[15]
		);
	return string;
}
