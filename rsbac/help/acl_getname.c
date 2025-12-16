/************************************ */
/* Rule Set Based Access Control      */
/*                                    */
/* Author and (c) 1999-2024: Amon Ott */
/*                                    */
/* Getname functions for ACL module   */
/* Last modified: 08/Jan/2024         */
/************************************ */

#include <rsbac/types.h>
#include <rsbac/getname.h>
#include <rsbac/acl_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#include <linux/string.h>

static char  acl_subject_type_list[ACLS_NONE+1][6] = {
                          "USER",
                          "ROLE",
                          "GROUP",
                          "NONE" };

static char  acl_group_syscall_list[ACLGS_none+1][18] = {
                          "add_group",
                          "change_group",
                          "remove_group",
                          "get_group_entry",
                          "list_groups",
                          "add_member",
                          "remove_member",
                          "get_user_groups",
                          "get_group_members",
                          "none" };

static char  acl_scd_type_list[AST_none-32+1][20] = {
                          "auth_administration",
                          "udf_administration",
                          "none" };

static char  acl_special_right_list[ACLR_NONE-32+1][20] = {
                          "FORWARD",
                          "ACCESS_CONTROL",
                          "SUPERVISOR",
                          "NONE" };

/*****************************************/

char * get_acl_subject_type_name(char * name,
                                 enum rsbac_acl_subject_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > ACLS_NONE)
      strcpy(name, "ERROR!");
    else
      strcpy(name, acl_subject_type_list[value]);
    return(name);
  };

char * get_acl_group_syscall_name(char * name,
                                  enum rsbac_acl_group_syscall_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > ACLGS_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, acl_group_syscall_list[value]);
    return(name);
  };

char * get_acl_scd_type_name(char * name,
                            enum rsbac_acl_scd_type_t value)
  {
    if(!name)
      return(NULL);
    if(value < AST_min)
      {
        return(get_scd_type_name(name, (enum rsbac_scd_type_t) value));
      }
    value -= AST_min;
    if(value > AST_none)
      {
        strcpy(name, "ERROR!");
        return(name);
      }
    strcpy(name, acl_scd_type_list[value]);
    return(name);
  };

char * get_acl_special_right_name(char * name,
                            enum rsbac_acl_special_rights_t value)
  {
    if(!name)
      return(NULL);
    if(value < RSBAC_ACL_SPECIAL_RIGHT_BASE)
      {
        return(get_request_name(name, (enum rsbac_adf_request_t) value));
      }
    value -= RSBAC_ACL_SPECIAL_RIGHT_BASE;
    if(value > ACLR_NONE)
      {
        strcpy(name, "ERROR!");
        return(name);
      }
    strcpy(name, acl_special_right_list[value]);
    return(name);
  };
