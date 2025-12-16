/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 1999-2021:        */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for CAP module */
/* Last modified: 04/Oct/2021       */
/********************************** */

#ifndef __RSBAC_NET_GETNAME_H
#define __RSBAC_NET_GETNAME_H

#include <rsbac/types.h>

#define RSBAC_NET_PROTO_MAX 256
#define RSBAC_NET_TYPE_MAX 11

extern int rsbac_net_str_to_inet(char * str, __u32 * addr);

extern char * rsbac_get_net_temp_syscall_name(char * name,
                                        enum rsbac_net_temp_syscall_t value);

extern char * rsbac_get_net_family_name(char * name,
                                  u_int value);

extern char * rsbac_get_net_netlink_family_name(char * name,
                                  u_int value);

extern char * rsbac_get_net_protocol_name(char * name,
                                    u_int value);

extern char * rsbac_get_net_type_name(char * name,
                                u_int value);

char * rsbac_net_inet6_to_str(char * string, void * inet6);

#endif
