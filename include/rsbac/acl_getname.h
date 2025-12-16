/********************************* */
/* Rule Set Based Access Control   */
/* Author and (c) 1999-2021:       */
/*   Amon Ott <ao@rsbac.org>       */
/* Getname functions for ACL parts */
/* Last modified: 04/Oct/2021      */
/********************************* */

#ifndef __RSBAC_ACL_GETNAME_H
#define __RSBAC_ACL_GETNAME_H

#include <rsbac/types.h>

char * get_acl_subject_type_name(char * name,
                                 enum rsbac_acl_subject_type_t value);

char * get_acl_group_syscall_name(char * name,
                                  enum rsbac_acl_group_syscall_type_t value);

char * get_acl_special_right_name(char * name,
                            enum rsbac_acl_special_rights_t value);

char * get_acl_scd_type_name(char * name,
                             enum rsbac_acl_scd_type_t value);

#endif
