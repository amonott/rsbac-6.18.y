/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2019:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Syscall wrapper functions for all   */
/* parts                               */
/* Last modified: 10/Dec/2019          */
/************************************* */

#ifndef __RSBAC_SYSCALLS_H
#define __RSBAC_SYSCALLS_H

#include <linux/unistd.h>
#include <rsbac/types.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
#include <asm/compat.h>
#endif

enum rsbac_syscall_t
  {
    RSYS_version,
    RSYS_stats,
    RSYS_check,
    RSYS_get_attr,
    RSYS_get_attr_n,
    RSYS_set_attr,
    RSYS_set_attr_n,
    RSYS_remove_target,
    RSYS_remove_target_n,
    RSYS_net_list_all_netdev,
    RSYS_net_template,
    RSYS_net_list_all_template,
    RSYS_switch,
    RSYS_get_switch,
    RSYS_adf_log_switch,
    RSYS_get_adf_log,
    RSYS_write,
    RSYS_log,
    RSYS_mac_set_curr_level,
    RSYS_mac_get_curr_level,
    RSYS_mac_get_max_level,
    RSYS_mac_get_min_level,
    RSYS_mac_add_p_tru,
    RSYS_mac_remove_p_tru,
    RSYS_mac_add_f_tru,
    RSYS_mac_remove_f_tru,
    RSYS_mac_get_f_trulist,
    RSYS_mac_get_p_trulist,
    RSYS_stats_pm,
    RSYS_pm,
    RSYS_pm_change_current_task,
    RSYS_pm_create_file,
    RSYS_daz_flush_cache,
    RSYS_rc_copy_role,
    RSYS_rc_copy_type,
    RSYS_rc_get_item,
    RSYS_rc_set_item,
    RSYS_rc_change_role,
    RSYS_rc_get_eff_rights_n,
    RSYS_rc_get_list,
    RSYS_auth_add_p_cap,
    RSYS_auth_remove_p_cap,
    RSYS_auth_add_f_cap,
    RSYS_auth_remove_f_cap,
    RSYS_auth_get_f_caplist,
    RSYS_auth_get_p_caplist,
    RSYS_acl,
    RSYS_acl_n,
    RSYS_acl_get_rights,
    RSYS_acl_get_rights_n,
    RSYS_acl_get_tlist,
    RSYS_acl_get_tlist_n,
    RSYS_acl_get_mask,
    RSYS_acl_get_mask_n,
    RSYS_acl_group,
    RSYS_reg,
    RSYS_jail,
    RSYS_init,
    RSYS_rc_get_current_role,
    RSYS_um_auth_name,
    RSYS_um_auth_uid,
    RSYS_um_add_user,
    RSYS_um_add_group,
    RSYS_um_add_gm,
    RSYS_um_mod_user,
    RSYS_um_mod_group,
    RSYS_um_get_user_item,
    RSYS_um_get_group_item,
    RSYS_um_remove_user,
    RSYS_um_remove_group,
    RSYS_um_remove_gm,
    RSYS_um_user_exists,
    RSYS_um_group_exists,
    RSYS_um_get_next_user,
    RSYS_um_get_user_list,
    RSYS_um_get_gm_list,
    RSYS_um_get_gm_user_list,
    RSYS_um_get_group_list,
    RSYS_um_get_uid,
    RSYS_um_get_gid,
    RSYS_um_set_pass,
    RSYS_um_set_pass_name,
    RSYS_um_set_group_pass,
    RSYS_um_check_account,
    RSYS_um_check_account_name,
    RSYS_list_ta_begin,
    RSYS_list_ta_refresh,
    RSYS_list_ta_commit,
    RSYS_list_ta_forget,
    RSYS_list_all_dev,
    RSYS_acl_list_all_dev,
    RSYS_list_all_user,
    RSYS_acl_list_all_user,
    RSYS_list_all_group,
    RSYS_acl_list_all_group,
    RSYS_list_all_ipc,
    RSYS_rc_select_fd_create_type,
    RSYS_um_select_vset,
    RSYS_um_add_onetime,
    RSYS_um_add_onetime_name,
    RSYS_um_remove_all_onetime,
    RSYS_um_remove_all_onetime_name,
    RSYS_um_count_onetime,
    RSYS_um_count_onetime_name,
    RSYS_list_ta_begin_name,
    RSYS_um_get_max_history,
    RSYS_um_get_max_history_name,
    RSYS_um_set_max_history,
    RSYS_um_set_max_history_name,
    RSYS_udf_flush_cache,
    RSYS_api_min_version,
    RSYS_api_max_version,
    RSYS_um_add_user_hash,
    RSYS_um_add_group_hash,
    RSYS_um_set_pass_hash,
    RSYS_um_set_pass_name_hash,
    RSYS_um_set_group_pass_hash,
    RSYS_um_add_onetime_hash,
    RSYS_um_add_onetime_name_hash,
    RSYS_res_get_user_limit,
    RSYS_res_set_user_limit,
    RSYS_res_get_file_limit,
    RSYS_res_set_file_limit,
    RSYS_none
  };


struct rsys_check_t
  {
    int correct;
    int check_inode;
  };

struct rsys_get_attr_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
    union rsbac_target_id_t __user * tid;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t __user * value;
          int inherit;
  };

struct rsys_get_attr_n_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          char __user * t_name;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t __user * value;
          int inherit;
  };

struct rsys_set_attr_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
    union rsbac_target_id_t __user * tid;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t __user * value;
  };

struct rsys_set_attr_n_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          char __user * t_name;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t __user * value;
  };

struct rsys_remove_target_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_target_id_t __user * tid;
  };

struct rsys_remove_target_n_t
  {
         rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
         char __user * t_name;
  };

struct rsys_net_list_all_netdev_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_netdev_id_t __user * id_p;
    u_long maxnum;
  };

struct rsys_net_template_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
          rsbac_net_temp_id_t id;
    union rsbac_net_temp_syscall_data_t __user * data_p;
  };

struct rsys_net_list_all_template_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_net_temp_id_t __user * id_p;
    u_long maxnum;
  };

struct rsys_switch_t
  {
    rsbac_enum_t module;
    int value;
  };

struct rsys_get_switch_t
  {
    rsbac_enum_t module;
    int __user * value_p;
    int __user * switchable_p;
  };

struct rsys_adf_log_switch_t
  {
    rsbac_enum_t request;
    rsbac_enum_t target;
    u_int        value;
  };

struct rsys_get_adf_log_t
  {
    rsbac_enum_t   request;
    rsbac_enum_t   target;
    u_int        __user * value_p;
  };

struct rsys_log_t
  {
    int type;
    char __user * buf;
    int len;
  };

struct rsys_mac_set_curr_level_t
  {
    rsbac_security_level_t level;
    rsbac_mac_category_vector_t __user * categories_p;
  };

struct rsys_mac_get_curr_level_t
  {
    rsbac_security_level_t      __user * level_p;
    rsbac_mac_category_vector_t __user * categories_p;
  };

struct rsys_mac_get_max_level_t
  {
    rsbac_security_level_t      __user * level_p;
    rsbac_mac_category_vector_t __user * categories_p;
  };

struct rsys_mac_get_min_level_t
  {
    rsbac_security_level_t      __user * level_p;
    rsbac_mac_category_vector_t __user * categories_p;
  };

struct rsys_mac_add_p_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t uid;
    rsbac_time_t ttl;
  };

struct rsys_mac_remove_p_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t uid;
  };

struct rsys_mac_add_f_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * filename;
    rsbac_uid_t uid;
    rsbac_time_t ttl;
  };

struct rsys_mac_remove_f_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * filename;
    rsbac_uid_t uid;
  };

struct rsys_mac_get_f_trulist_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * filename;
    rsbac_uid_t __user * trulist;
    rsbac_time_t __user * ttllist;
    u_int maxnum;
  };

struct rsys_mac_get_p_trulist_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t __user * trulist;
    rsbac_time_t __user * ttllist;
    u_int maxnum;
  };

struct rsys_rc_copy_role_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_rc_role_id_t from_role;
    rsbac_rc_role_id_t to_role;
  };

struct rsys_rc_copy_type_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    rsbac_rc_type_id_t from_type;
    rsbac_rc_type_id_t to_type;
  };

struct rsys_rc_get_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t __user * tid_p;
    union rsbac_rc_target_id_t __user * subtid_p;
          rsbac_enum_t item;
    union rsbac_rc_item_value_t __user * value_p;
          rsbac_time_t __user * ttl_p;
  };

struct rsys_rc_set_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t __user * tid_p;
    union rsbac_rc_target_id_t __user * subtid_p;
          rsbac_enum_t item;
    union rsbac_rc_item_value_t __user * value_p;
          rsbac_time_t ttl;
  };

struct rsys_rc_get_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t __user * tid_p;
          rsbac_enum_t item;
          u_int maxnum;
          __u32 __user * array_p;
          rsbac_time_t __user * ttl_array_p;
  };

struct rsys_rc_change_role_t
  {
    rsbac_rc_role_id_t role;
    char __user * pass;
  };

struct rsys_rc_get_eff_rights_n_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    char __user * t_name;
    rsbac_rc_request_vector_t __user * request_vector_p;
    rsbac_time_t __user * ttl_p;
  };

struct rsys_rc_get_current_role_t
  {
    rsbac_rc_role_id_t __user * role_p;
  };

struct rsys_auth_add_p_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
           rsbac_time_t ttl;
  };

struct rsys_auth_remove_p_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
  };

struct rsys_auth_add_f_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           char __user * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
           rsbac_time_t ttl;
  };

struct rsys_auth_remove_f_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           char __user * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
  };

struct rsys_auth_get_f_caplist_t
  {
           rsbac_list_ta_number_t ta_number;
           char __user * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t __user * caplist;
           rsbac_time_t __user * ttllist;
           u_int maxnum;
  };

struct rsys_auth_get_p_caplist_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t __user * caplist;
           rsbac_time_t __user * ttllist;
           u_int maxnum;
  };

struct rsys_acl_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
    struct rsbac_acl_syscall_arg_t __user * arg;
  };

struct rsys_acl_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
    struct rsbac_acl_syscall_n_arg_t __user * arg;
  };

struct rsys_acl_get_rights_t
  {
           rsbac_list_ta_number_t ta_number;
    struct rsbac_acl_syscall_arg_t __user * arg;
           rsbac_acl_rights_vector_t __user * rights_p;
           u_int effective;
  };

struct rsys_acl_get_rights_n_t
  {
           rsbac_list_ta_number_t ta_number;
    struct rsbac_acl_syscall_n_arg_t __user * arg;
           rsbac_acl_rights_vector_t __user * rights_p;
           u_int effective;
  };

struct rsys_acl_get_tlist_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
    union  rsbac_target_id_t __user * tid;
    struct rsbac_acl_entry_t __user * entry_array;
           rsbac_time_t __user * ttl_array;
           u_int maxnum;
  };

struct rsys_acl_get_tlist_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           char __user * t_name;
    struct rsbac_acl_entry_t __user * entry_array;
           rsbac_time_t __user * ttl_array;
           u_int maxnum;
  };

struct rsys_acl_get_mask_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
    union  rsbac_target_id_t __user * tid;
           rsbac_acl_rights_vector_t __user * mask_p;
  };

struct rsys_acl_get_mask_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           char __user * t_name;
           rsbac_acl_rights_vector_t __user * mask_p;
  };

struct rsys_acl_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
    union rsbac_acl_group_syscall_arg_t __user * arg_p;
  };

struct rsys_reg_t
  {
    long handle;
    void __user * arg;
  };

struct rsys_jail_t
  {
    rsbac_version_t      version;
    char               __user * path;
    rsbac_jail_ip_t      ip;
    rsbac_jail_flags_t   flags;
    rsbac_cap_vector_t   max_caps;
    rsbac_jail_scd_vector_t scd_get;
    rsbac_jail_scd_vector_t scd_modify;
  };

struct rsys_init_t
  {
    char __user * root_dev;
  };

struct rsys_um_auth_name_t
  {
    char __user * name;
    char __user * pass;
  };

struct rsys_um_auth_uid_t
  {
    rsbac_uid_t   uid;
    char        __user * pass;
  };

struct rsys_um_add_user_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_t             uid;
    struct rsbac_um_user_entry_t __user * entry_p;
           char                  __user * pass;
           rsbac_time_t            ttl;
  };

struct rsys_um_add_user_hash_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_t             uid;
    struct rsbac_um_user_entry_t __user * entry_p;
           char                  __user * pass;
    const  char                  __user * hash_algo;
           rsbac_time_t            ttl;
  };

struct rsys_um_add_group_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_gid_t              gid;
    struct rsbac_um_group_entry_t __user * entry_p;
           char                   __user * pass;
           rsbac_time_t             ttl;
  };

struct rsys_um_add_group_hash_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_gid_t              gid;
    struct rsbac_um_group_entry_t __user * entry_p;
           char                   __user * pass;
    const  char                   __user * hash_algo;
           rsbac_time_t             ttl;
  };

struct rsys_um_add_gm_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_t  uid;
           rsbac_gid_num_t  gid;
           rsbac_time_t ttl;
  };

struct rsys_um_mod_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t __user * data_p;
  };

struct rsys_um_mod_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t __user * data_p;
  };

struct rsys_um_get_user_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t __user * data_p;
  };

struct rsys_um_get_group_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t __user * data_p;
  };

struct rsys_um_remove_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
  };

struct rsys_um_remove_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
  };

struct rsys_um_remove_gm_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t  uid;
          rsbac_gid_num_t  gid;
  };

struct rsys_um_user_exists_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t uid;
  };

struct rsys_um_group_exists_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t gid;
  };

struct rsys_um_get_next_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t   old_user;
          rsbac_uid_t __user * next_user_p;
  };

struct rsys_um_get_user_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          rsbac_uid_t __user * user_array;
          u_int         maxnum;
  };

struct rsys_um_get_gm_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t   user;
          rsbac_gid_num_t __user * group_array;
          u_int         maxnum;
  };

struct rsys_um_get_gm_user_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t   group;
          rsbac_uid_num_t __user * user_array;
          u_int         maxnum;
  };

struct rsys_um_get_group_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          rsbac_gid_t __user * group_array;
          u_int         maxnum;
  };

struct rsys_um_get_uid_t
  {
    rsbac_list_ta_number_t ta_number;
    char        __user * name;
    rsbac_uid_t __user * uid_p;
  };

struct rsys_um_get_gid_t
  {
    rsbac_list_ta_number_t ta_number;
    char        __user * name;
    rsbac_gid_t __user * gid_p;
  };

struct rsys_um_set_pass_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
    char        __user * new_pass;
  };

struct rsys_um_set_pass_name_t
  {
    char __user * name;
    char __user * old_pass;
    char __user * new_pass;
  };

struct rsys_um_set_pass_hash_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
    char        __user * new_pass;
    const  char __user * hash_algo;
  };

struct rsys_um_set_pass_name_hash_t
  {
    char __user * name;
    char __user * old_pass;
    char __user * new_pass;
    const  char __user * hash_algo;
  };

struct rsys_um_add_onetime_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
    char        __user * new_pass;
    rsbac_time_t  ttl;
  };

struct rsys_um_add_onetime_name_t
  {
    char __user * name;
    char __user * old_pass;
    char __user * new_pass;
    rsbac_time_t ttl;
  };

struct rsys_um_add_onetime_hash_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
    char        __user * new_pass;
    char        __user * hash_algo;
    rsbac_time_t  ttl;
  };

struct rsys_um_add_onetime_name_hash_t
  {
    char __user * name;
    char __user * old_pass;
    char __user * new_pass;
    char __user * hash_algo;
    rsbac_time_t ttl;
  };

struct rsys_um_remove_all_onetime_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
  };

struct rsys_um_remove_all_onetime_name_t
  {
    char __user * name;
    char __user * old_pass;
  };

struct rsys_um_count_onetime_t
  {
    rsbac_uid_t   uid;
    char        __user * old_pass;
  };

struct rsys_um_count_onetime_name_t
  {
    char __user * name;
    char __user * old_pass;
  };

struct rsys_um_set_group_pass_t
  {
    rsbac_gid_t   gid;
    char        __user * new_pass;
  };

struct rsys_um_set_group_pass_hash_t
  {
    rsbac_gid_t   gid;
    char        __user * new_pass;
    const  char __user * hash_algo;
  };

struct rsys_um_check_account_t
  {
    rsbac_uid_t   uid;
  };

struct rsys_um_check_account_name_t
  {
    char __user * name;
  };

struct rsys_um_get_max_history_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t   uid;
  };

struct rsys_um_get_max_history_name_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * name;
  };

struct rsys_um_set_max_history_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t   uid;
    __u8          max_history;
  };

struct rsys_um_set_max_history_name_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * name;
    __u8   max_history;
  };

struct rsys_um_select_vset_t
  {
    rsbac_um_set_t vset;
  };

struct rsys_list_ta_begin_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t __user * ta_number_p;
    rsbac_uid_t commit_uid;
    char __user * password;
  };

struct rsys_list_ta_begin_name_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t __user * ta_number_p;
    rsbac_uid_t commit_uid;
    char __user * name;
    char __user * password;
  };

struct rsys_list_ta_refresh_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t ta_number;
    char __user * password;
  };

struct rsys_list_ta_commit_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * password;
  };

struct rsys_list_ta_forget_t
  {
    rsbac_list_ta_number_t ta_number;
    char __user * password;
  };

struct rsys_list_all_dev_t
  {
    rsbac_list_ta_number_t ta_number;
    struct rsbac_dev_desc_t __user * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_dev_t
  {
    rsbac_list_ta_number_t ta_number;
    struct rsbac_dev_desc_t __user * id_p;
    u_long maxnum;
  };

struct rsys_list_all_user_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t __user * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_user_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t __user * id_p;
    u_long maxnum;
  };

struct rsys_list_all_group_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_gid_t __user * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_group_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_gid_t __user * id_p;
    u_long maxnum;
  };

struct rsys_list_all_ipc_t {
       rsbac_list_ta_number_t ta_number;
       struct rsbac_ipc_t __user *id_p;
       u_long maxnum;
};

struct rsys_rc_select_fd_create_type_t {
	rsbac_rc_type_id_t type;
};

struct rsys_res_get_user_limit_t
  {
	rsbac_list_ta_number_t ta_number;
	rsbac_uid_t uid;
	enum rsbac_attribute_t attr;
	rsbac_res_desc_t res_num;
	rsbac_res_limit_t __user * value_p;
	rsbac_time_t __user * ttl_p;
	rsbac_boolean_t inherit;
  };

struct rsys_res_set_user_limit_t
  {
	rsbac_list_ta_number_t ta_number;
	rsbac_uid_t uid;
	enum rsbac_attribute_t attr;
	rsbac_res_desc_t res_num;
	rsbac_res_limit_t __user * value_p;
	rsbac_time_t ttl;
  };

struct rsys_res_get_file_limit_t
  {
	rsbac_list_ta_number_t ta_number;
	char __user * t_name;
	enum rsbac_attribute_t attr;
	rsbac_res_desc_t res_num;
	rsbac_res_limit_t __user * value_p;
	rsbac_time_t __user * ttl_p;
  };

struct rsys_res_set_file_limit_t
  {
	rsbac_list_ta_number_t ta_number;
	char __user * t_name;
	enum rsbac_attribute_t attr;
	rsbac_res_desc_t res_num;
	rsbac_res_limit_t __user * value_p;
	rsbac_time_t ttl;
  };

union rsbac_syscall_arg_t
  {
    struct rsys_check_t check;
    struct rsys_get_attr_t get_attr;
    struct rsys_get_attr_n_t get_attr_n;
    struct rsys_set_attr_t set_attr;
    struct rsys_set_attr_n_t set_attr_n;
    struct rsys_remove_target_t remove_target;
    struct rsys_remove_target_n_t remove_target_n;
    struct rsys_net_list_all_netdev_t net_list_all_netdev;
    struct rsys_net_template_t net_template;
    struct rsys_net_list_all_template_t net_list_all_template;
    struct rsys_switch_t switch_module;
    struct rsys_get_switch_t get_switch_module;
    struct rsys_adf_log_switch_t adf_log_switch;
    struct rsys_get_adf_log_t get_adf_log;
    struct rsys_log_t log;
    struct rsys_mac_set_curr_level_t mac_set_curr_level;
    struct rsys_mac_get_curr_level_t mac_get_curr_level;
    struct rsys_mac_get_max_level_t mac_get_max_level;
    struct rsys_mac_get_min_level_t mac_get_min_level;
    struct rsys_mac_add_p_tru_t mac_add_p_tru;
    struct rsys_mac_remove_p_tru_t mac_remove_p_tru;
    struct rsys_mac_add_f_tru_t mac_add_f_tru;
    struct rsys_mac_remove_f_tru_t mac_remove_f_tru;
    struct rsys_mac_get_f_trulist_t mac_get_f_trulist;
    struct rsys_mac_get_p_trulist_t mac_get_p_trulist;
    struct rsys_rc_copy_role_t rc_copy_role;
    struct rsys_rc_copy_type_t rc_copy_type;
    struct rsys_rc_get_item_t rc_get_item;
    struct rsys_rc_set_item_t rc_set_item;
    struct rsys_rc_get_list_t rc_get_list;
    struct rsys_rc_change_role_t rc_change_role;
    struct rsys_rc_get_eff_rights_n_t rc_get_eff_rights_n;
    struct rsys_rc_get_current_role_t rc_get_current_role;
    struct rsys_auth_add_p_cap_t auth_add_p_cap;
    struct rsys_auth_remove_p_cap_t auth_remove_p_cap;
    struct rsys_auth_add_f_cap_t auth_add_f_cap;
    struct rsys_auth_remove_f_cap_t auth_remove_f_cap;
    struct rsys_auth_get_f_caplist_t auth_get_f_caplist;
    struct rsys_auth_get_p_caplist_t auth_get_p_caplist;
    struct rsys_acl_t acl;
    struct rsys_acl_n_t acl_n;
    struct rsys_acl_get_rights_t acl_get_rights;
    struct rsys_acl_get_rights_n_t acl_get_rights_n;
    struct rsys_acl_get_tlist_t acl_get_tlist;
    struct rsys_acl_get_tlist_n_t acl_get_tlist_n;
    struct rsys_acl_get_mask_t acl_get_mask;
    struct rsys_acl_get_mask_n_t acl_get_mask_n;
    struct rsys_acl_group_t acl_group;
    struct rsys_reg_t reg;
    struct rsys_jail_t jail;
    struct rsys_init_t init;
    struct rsys_um_auth_name_t um_auth_name;
    struct rsys_um_auth_uid_t um_auth_uid;
    struct rsys_um_add_user_t um_add_user;
    struct rsys_um_add_group_t um_add_group;
    struct rsys_um_add_gm_t um_add_gm;
    struct rsys_um_mod_user_t um_mod_user;
    struct rsys_um_mod_group_t um_mod_group;
    struct rsys_um_get_user_item_t um_get_user_item;
    struct rsys_um_get_group_item_t um_get_group_item;
    struct rsys_um_remove_user_t um_remove_user;
    struct rsys_um_remove_group_t um_remove_group;
    struct rsys_um_remove_gm_t um_remove_gm;
    struct rsys_um_user_exists_t um_user_exists;
    struct rsys_um_group_exists_t um_group_exists;
    struct rsys_um_get_next_user_t um_get_next_user;
    struct rsys_um_get_user_list_t um_get_user_list;
    struct rsys_um_get_gm_list_t um_get_gm_list;
    struct rsys_um_get_gm_user_list_t um_get_gm_user_list;
    struct rsys_um_get_group_list_t um_get_group_list;
    struct rsys_um_get_uid_t um_get_uid;
    struct rsys_um_get_gid_t um_get_gid;
    struct rsys_um_set_pass_t um_set_pass;
    struct rsys_um_set_pass_name_t um_set_pass_name;
    struct rsys_um_add_onetime_t um_add_onetime;
    struct rsys_um_add_onetime_name_t um_add_onetime_name;
    struct rsys_um_remove_all_onetime_t um_remove_all_onetime;
    struct rsys_um_remove_all_onetime_name_t um_remove_all_onetime_name;
    struct rsys_um_count_onetime_t um_count_onetime;
    struct rsys_um_count_onetime_name_t um_count_onetime_name;
    struct rsys_um_set_group_pass_t um_set_group_pass;
    struct rsys_um_check_account_t um_check_account;
    struct rsys_um_check_account_name_t um_check_account_name;
    struct rsys_um_get_max_history_t um_get_max_history;
    struct rsys_um_get_max_history_name_t um_get_max_history_name;
    struct rsys_um_set_max_history_t um_set_max_history;
    struct rsys_um_set_max_history_name_t um_set_max_history_name;
    struct rsys_list_ta_begin_t list_ta_begin;
    struct rsys_list_ta_begin_name_t list_ta_begin_name;
    struct rsys_list_ta_refresh_t list_ta_refresh;
    struct rsys_list_ta_commit_t list_ta_commit;
    struct rsys_list_ta_forget_t list_ta_forget;
    struct rsys_list_all_dev_t list_all_dev;
    struct rsys_acl_list_all_dev_t acl_list_all_dev;
    struct rsys_list_all_user_t list_all_user;
    struct rsys_acl_list_all_user_t acl_list_all_user;
    struct rsys_list_all_group_t list_all_group;
    struct rsys_acl_list_all_group_t acl_list_all_group;
    struct rsys_list_all_ipc_t list_all_ipc;
    struct rsys_rc_select_fd_create_type_t rc_select_fd_create_type;
    struct rsys_um_select_vset_t um_select_vset;
    struct rsys_um_add_user_hash_t um_add_user_hash;
    struct rsys_um_add_group_hash_t um_add_group_hash;
    struct rsys_um_set_pass_hash_t um_set_pass_hash;
    struct rsys_um_set_pass_name_hash_t um_set_pass_name_hash;
    struct rsys_um_set_group_pass_hash_t um_set_group_pass_hash;
    struct rsys_um_add_onetime_hash_t um_add_onetime_hash;
    struct rsys_um_add_onetime_name_hash_t um_add_onetime_name_hash;
    struct rsys_res_get_user_limit_t res_get_user_limit;
    struct rsys_res_set_user_limit_t res_set_user_limit;
    struct rsys_res_get_file_limit_t res_get_file_limit;
    struct rsys_res_set_file_limit_t res_set_file_limit;
           int dummy;
  };

/*
 * 32 Bit emulation support on x86_64 system
 */

#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
struct rsys_check_ia32_t
  {
    __s32 correct;
    __s32 check_inode;
  } __attribute__ ((aligned (4)));

struct rsys_get_attr_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          __u32 tid;
          rsbac_enum_t attr;
          __u32 value;
          __s32 inherit;
  } __attribute__ ((aligned (4)));

struct rsys_get_attr_n_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          __u32 t_name;
          rsbac_enum_t attr;
          __u32 value;
          __s32 inherit;
  } __attribute__ ((aligned (4)));

struct rsys_set_attr_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          __u32 tid;
          rsbac_enum_t attr;
          __u32 value;
  } __attribute__ ((aligned (4)));

struct rsys_set_attr_n_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          __u32 t_name;
          rsbac_enum_t attr;
          __u32 value;
  } __attribute__ ((aligned (4)));

struct rsys_remove_target_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
          __u32 tid;
  } __attribute__ ((aligned (4)));

struct rsys_remove_target_n_ia32_t
  {
         rsbac_list_ta_number_t ta_number;
         rsbac_enum_t target;
         __u32 t_name;
  } __attribute__ ((aligned (4)));

struct rsys_net_list_all_netdev_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_net_template_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
          rsbac_net_temp_id_t id;
          __u32 data_p;
  } __attribute__ ((aligned (4)));

struct rsys_net_list_all_template_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_switch_ia32_t
  {
    rsbac_enum_t module;
    __s32 value;
  } __attribute__ ((aligned (4)));

struct rsys_get_switch_ia32_t
  {
    rsbac_enum_t module;
    __u32 value_p;
    __u32 switchable_p;
  } __attribute__ ((aligned (4)));

struct rsys_adf_log_switch_ia32_t
  {
    rsbac_enum_t request;
    rsbac_enum_t target;
    __u32        value;
  } __attribute__ ((aligned (4)));

struct rsys_get_adf_log_ia32_t
  {
    rsbac_enum_t   request;
    rsbac_enum_t   target;
    __u32 value_p;
  } __attribute__ ((aligned (4)));

struct rsys_log_ia32_t
  {
    __u32 type;
    __u32 buf;
    __u32 len;
  } __attribute__ ((aligned (4)));

struct rsys_mac_set_curr_level_ia32_t
  {
    rsbac_security_level_t level;
    __u32 categories_p;
  } __attribute__ ((aligned (4)));

struct rsys_mac_get_curr_level_ia32_t
  {
    __u32 level_p;
    __u32 categories_p;
  } __attribute__ ((aligned (4)));

struct rsys_mac_get_max_level_ia32_t
  {
    __u32 level_p;
    __u32 categories_p;
  } __attribute__ ((aligned (4)));

struct rsys_mac_get_min_level_ia32_t
  {
    __u32 level_p;
    __u32 categories_p;
  } __attribute__ ((aligned (4)));

struct rsys_mac_add_p_tru_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    compat_pid_t pid;
    rsbac_uid_ia32_t uid;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_mac_remove_p_tru_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    compat_pid_t pid;
    rsbac_uid_ia32_t uid;
  } __attribute__ ((aligned (4)));

struct rsys_mac_add_f_tru_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 filename;
    rsbac_uid_ia32_t uid;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_mac_remove_f_tru_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 filename;
    rsbac_uid_ia32_t uid;
  } __attribute__ ((aligned (4)));

struct rsys_mac_get_f_trulist_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 filename;
    __u32 trulist;
    __u32 ttllist;
    __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_mac_get_p_trulist_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    compat_pid_t pid;
    __u32 trulist;
    __u32 ttllist;
    __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_rc_copy_role_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_rc_role_id_t from_role;
    rsbac_rc_role_id_t to_role;
  } __attribute__ ((aligned (4)));

struct rsys_rc_copy_type_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    rsbac_rc_type_id_t from_type;
    rsbac_rc_type_id_t to_type;
  } __attribute__ ((aligned (4)));

struct rsys_rc_get_item_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
          __u32 tid_p;
          __u32 subtid_p;
          rsbac_enum_t item;
          __u32 value_p;
          __u32 ttl_p;
  } __attribute__ ((aligned (4)));

struct rsys_rc_set_item_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
          __u32 tid_p;
          __u32 subtid_p;
          rsbac_enum_t item;
          __u32 value_p;
          rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_rc_get_list_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
          __u32 tid_p;
          rsbac_enum_t item;
          __u32 maxnum;
          __u32 array_p;
          __u32 ttl_array_p;
  } __attribute__ ((aligned (4)));

struct rsys_rc_change_role_ia32_t
  {
    rsbac_rc_role_id_t role;
    __u32 pass;
  } __attribute__ ((aligned (4)));

struct rsys_rc_get_eff_rights_n_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    __u32 t_name;
    __u32 request_vector_p;
    __u32 ttl_p;
  } __attribute__ ((aligned (4)));

struct rsys_rc_get_current_role_ia32_t
  {
    __u32 role_p;
  } __attribute__ ((aligned (4)));

struct rsys_auth_add_p_cap_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           compat_pid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_ia32_t cap_range;
           rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_auth_remove_p_cap_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           compat_pid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_ia32_t cap_range;
  } __attribute__ ((aligned (4)));

struct rsys_auth_add_f_cap_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           __u32 filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_ia32_t cap_range;
           rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_auth_remove_f_cap_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           __u32 filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_ia32_t cap_range;
  } __attribute__ ((aligned (4)));

struct rsys_auth_get_f_caplist_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           __u32 filename;
           rsbac_enum_t cap_type;
           __u32 caplist;
           __u32 ttllist;
           __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_auth_get_p_caplist_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           compat_pid_t pid;
           rsbac_enum_t cap_type;
           __u32 caplist;
           __u32 ttllist;
           __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
           __u32 arg;
  } __attribute__ ((aligned (4)));

struct rsys_acl_n_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
           __u32 arg;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_rights_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           __u32 arg;
           __u32 rights_p;
           __u32 effective;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_rights_n_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           __u32 arg;
           __u32 rights_p;
           __u32 effective;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_tlist_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           __u32 tid;
           __u32 entry_array;
           __u32 ttl_array;
           __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_tlist_n_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           __u32 t_name;
           __u32 entry_array;
           __u32 ttl_array;
           __u32 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_mask_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           __u32 tid;
           __u32 mask_p;
  } __attribute__ ((aligned (4)));

struct rsys_acl_get_mask_n_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           __u32 t_name;
           __u32 mask_p;
  } __attribute__ ((aligned (4)));

struct rsys_acl_group_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
          __u32 arg_p;
  } __attribute__ ((aligned (4)));

struct rsys_reg_ia32_t
  {
    compat_s64 handle;
    __u32 arg;
  } __attribute__ ((aligned (4)));

struct rsys_jail_ia32_t
  {
    rsbac_version_t      version;
    __u32                path;
    rsbac_jail_ip_t      ip;
    rsbac_jail_flags_t   flags;
    rsbac_cap_vector_t   max_caps;
    rsbac_jail_scd_vector_t scd_get;
    rsbac_jail_scd_vector_t scd_modify;
  } __attribute__ ((aligned (4)));

struct rsys_init_ia32_t
  {
    __u32 root_dev;
  } __attribute__ ((aligned (4)));

struct rsys_um_auth_name_ia32_t
  {
    __u32 name;
    __u32 pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_auth_uid_ia32_t
  {
    rsbac_uid_ia32_t uid;
    __u32       pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_user_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_ia32_t             uid;
           __u32                   entry_p;
           __u32                   pass;
           rsbac_time_t            ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_group_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_gid_ia32_t              gid;
           __u32                    entry_p;
           __u32                    pass;
           rsbac_time_t             ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_user_hash_ia32_t
  {
           rsbac_list_ta_number_t  ta_number;
           rsbac_uid_ia32_t        uid;
           __u32                   entry_p;
           __u32                   pass;
           __u32                   hash_algo;
           rsbac_time_t            ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_group_hash_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_gid_ia32_t       gid;
           __u32                  entry_p;
           __u32                  pass;
           __u32                  hash_algo;
           rsbac_time_t           ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_gm_ia32_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_ia32_t  uid;
           rsbac_gid_num_t  gid;
           rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_mod_user_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t           uid;
          rsbac_enum_t          mod;
          __u32                 data_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_mod_group_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_ia32_t            gid;
          rsbac_enum_t           mod;
          __u32                  data_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_user_item_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t            uid;
          rsbac_enum_t           mod;
          __u32                  data_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_group_item_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_ia32_t            gid;
          rsbac_enum_t           mod;
          __u32                  data_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_remove_user_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t           uid;
  } __attribute__ ((aligned (4)));

struct rsys_um_remove_group_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_ia32_t           gid;
  } __attribute__ ((aligned (4)));

struct rsys_um_remove_gm_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t  uid;
          rsbac_gid_num_t  gid;
  } __attribute__ ((aligned (4)));

struct rsys_um_user_exists_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t uid;
  } __attribute__ ((aligned (4)));

struct rsys_um_group_exists_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_ia32_t gid;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_next_user_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t   old_user;
          __u32         next_user_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_user_list_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          __u32          user_array;
          u_int          maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_gm_list_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_ia32_t   user;
          __u32         group_array;
          u_int         maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_gm_user_list_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_ia32_t   group;
          __u32         user_array;
          u_int         maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_group_list_ia32_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          __u32          group_array;
          u_int          maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_uid_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32                  name;
    __u32                  uid_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_gid_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32                  name;
    __u32                  gid_p;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_pass_ia32_t
  {
    rsbac_uid_ia32_t uid;
    __u32       old_pass;
    __u32       new_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_pass_name_ia32_t
  {
    __u32 name;
    __u32 old_pass;
    __u32 new_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_pass_hash_ia32_t
  {
    rsbac_uid_ia32_t uid;
    __u32 old_pass;
    __u32 new_pass;
    __u32 hash_algo;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_pass_name_hash_ia32_t
  {
    __u32 name;
    __u32 old_pass;
    __u32 new_pass;
    __u32 hash_algo;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_onetime_ia32_t
  {
    rsbac_uid_ia32_t  uid;
    __u32        old_pass;
    __u32        new_pass;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_onetime_name_ia32_t
  {
    __u32 name;
    __u32 old_pass;
    __u32 new_pass;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_onetime_hash_ia32_t
  {
    rsbac_uid_ia32_t  uid;
    __u32        old_pass;
    __u32        new_pass;
    __u32        hash_algo;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_add_onetime_name_hash_ia32_t
  {
    __u32 name;
    __u32 old_pass;
    __u32 new_pass;
    __u32 hash_algo;
    rsbac_time_t ttl;
  } __attribute__ ((aligned (4)));

struct rsys_um_remove_all_onetime_ia32_t
  {
    rsbac_uid_ia32_t uid;
    __u32       old_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_remove_all_onetime_name_ia32_t
  {
    __u32 name;
    __u32 old_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_count_onetime_ia32_t
  {
    rsbac_uid_ia32_t uid;
    __u32       old_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_count_onetime_name_ia32_t
  {
    __u32 name;
    __u32 old_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_group_pass_ia32_t
  {
    rsbac_gid_ia32_t gid;
    __u32       new_pass;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_group_pass_hash_ia32_t
  {
    rsbac_gid_ia32_t gid;
    __u32            new_pass;
    __u32            hash_algo;
  } __attribute__ ((aligned (4)));

struct rsys_um_check_account_ia32_t
  {
    rsbac_uid_ia32_t   uid;
  } __attribute__ ((aligned (4)));

struct rsys_um_check_account_name_ia32_t
  {
    __u32 name;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_max_history_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_ia32_t   uid;
  } __attribute__ ((aligned (4)));

struct rsys_um_get_max_history_name_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 name;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_max_history_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_ia32_t   uid;
    __u8          max_history;
  } __attribute__ ((aligned (4)));

struct rsys_um_set_max_history_name_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 name;
    __u8   max_history;
  } __attribute__ ((aligned (4)));

struct rsys_um_select_vset_ia32_t
  {
    rsbac_um_set_t vset;
  } __attribute__ ((aligned (4)));

struct rsys_list_ta_begin_ia32_t
  {
    rsbac_time_t ttl;
    __u32        ta_number_p;
    rsbac_uid_ia32_t  commit_uid;
    __u32        password;
  } __attribute__ ((aligned (4)));

struct rsys_list_ta_begin_name_ia32_t
  {
    rsbac_time_t ttl;
    __u32 ta_number_p;
    rsbac_uid_ia32_t commit_uid;
    __u32 name;
    __u32 password;
  } __attribute__ ((aligned (4)));

struct rsys_list_ta_refresh_ia32_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t ta_number;
    __u32 password;
  } __attribute__ ((aligned (4)));

struct rsys_list_ta_commit_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 password;
  } __attribute__ ((aligned (4)));

struct rsys_list_ta_forget_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 password;
  } __attribute__ ((aligned (4)));

struct rsys_list_all_dev_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_list_all_dev_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_list_all_user_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_list_all_user_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_list_all_group_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_acl_list_all_group_ia32_t
  {
    rsbac_list_ta_number_t ta_number;
    __u32 id_p;
    compat_u64 maxnum;
  } __attribute__ ((aligned (4)));

struct rsys_list_all_ipc_ia32_t
{
       rsbac_list_ta_number_t ta_number;
       __u32 id_p;
       compat_u64 maxnum;
} __attribute__ ((aligned (4)));

struct rsys_rc_select_fd_create_type_ia32_t
{
	rsbac_rc_type_id_t type;
} __attribute__ ((aligned (4)));

struct rsys_res_get_user_limit_ia32_t
{
	rsbac_list_ta_number_t ta_number;
	rsbac_uid_ia32_t uid;
	rsbac_enum_t attr;
	rsbac_res_desc_t res_num;
	__u32 value_p;
	__u32 ttl_p;
	__s32 inherit;
} __attribute__ ((aligned (4)));

struct rsys_res_set_user_limit_ia32_t
{
	rsbac_list_ta_number_t ta_number;
	rsbac_uid_ia32_t uid;
	rsbac_enum_t attr;
	rsbac_res_desc_t res_num;
	__u32 value_p;
	rsbac_time_t ttl;
} __attribute__ ((aligned (4)));

struct rsys_res_get_file_limit_ia32_t
{
	rsbac_list_ta_number_t ta_number;
	__u32 t_name;
	rsbac_enum_t attr;
	rsbac_res_desc_t res_num;
	__u32 value_p;
	__u32 ttl_p;
} __attribute__ ((aligned (4)));

struct rsys_res_set_file_limit_ia32_t
{
	rsbac_list_ta_number_t ta_number;
	__u32 t_name;
	rsbac_enum_t attr;
	rsbac_res_desc_t res_num;
	__u32 value_p;
	rsbac_time_t ttl;
} __attribute__ ((aligned (4)));

union rsbac_syscall_arg_ia32_t
  {
    struct rsys_check_ia32_t check;
    struct rsys_get_attr_ia32_t get_attr;
    struct rsys_get_attr_n_ia32_t get_attr_n;
    struct rsys_set_attr_ia32_t set_attr;
    struct rsys_set_attr_n_ia32_t set_attr_n;
    struct rsys_remove_target_ia32_t remove_target;
    struct rsys_remove_target_n_ia32_t remove_target_n;
    struct rsys_net_list_all_netdev_ia32_t net_list_all_netdev;
    struct rsys_net_template_ia32_t net_template;
    struct rsys_net_list_all_template_ia32_t net_list_all_template;
    struct rsys_switch_ia32_t switch_module;
    struct rsys_get_switch_ia32_t get_switch_module;
    struct rsys_adf_log_switch_ia32_t adf_log_switch;
    struct rsys_get_adf_log_ia32_t get_adf_log;
    struct rsys_log_ia32_t log;
    struct rsys_mac_set_curr_level_ia32_t mac_set_curr_level;
    struct rsys_mac_get_curr_level_ia32_t mac_get_curr_level;
    struct rsys_mac_get_max_level_ia32_t mac_get_max_level;
    struct rsys_mac_get_min_level_ia32_t mac_get_min_level;
    struct rsys_mac_add_p_tru_ia32_t mac_add_p_tru;
    struct rsys_mac_remove_p_tru_ia32_t mac_remove_p_tru;
    struct rsys_mac_add_f_tru_ia32_t mac_add_f_tru;
    struct rsys_mac_remove_f_tru_ia32_t mac_remove_f_tru;
    struct rsys_mac_get_f_trulist_ia32_t mac_get_f_trulist;
    struct rsys_mac_get_p_trulist_ia32_t mac_get_p_trulist;
    struct rsys_rc_copy_role_ia32_t rc_copy_role;
    struct rsys_rc_copy_type_ia32_t rc_copy_type;
    struct rsys_rc_get_item_ia32_t rc_get_item;
    struct rsys_rc_set_item_ia32_t rc_set_item;
    struct rsys_rc_get_list_ia32_t rc_get_list;
    struct rsys_rc_change_role_ia32_t rc_change_role;
    struct rsys_rc_get_eff_rights_n_ia32_t rc_get_eff_rights_n;
    struct rsys_rc_get_current_role_ia32_t rc_get_current_role;
    struct rsys_auth_add_p_cap_ia32_t auth_add_p_cap;
    struct rsys_auth_remove_p_cap_ia32_t auth_remove_p_cap;
    struct rsys_auth_add_f_cap_ia32_t auth_add_f_cap;
    struct rsys_auth_remove_f_cap_ia32_t auth_remove_f_cap;
    struct rsys_auth_get_f_caplist_ia32_t auth_get_f_caplist;
    struct rsys_auth_get_p_caplist_ia32_t auth_get_p_caplist;
    struct rsys_acl_ia32_t acl;
    struct rsys_acl_n_ia32_t acl_n;
    struct rsys_acl_get_rights_ia32_t acl_get_rights;
    struct rsys_acl_get_rights_n_ia32_t acl_get_rights_n;
    struct rsys_acl_get_tlist_ia32_t acl_get_tlist;
    struct rsys_acl_get_tlist_n_ia32_t acl_get_tlist_n;
    struct rsys_acl_get_mask_ia32_t acl_get_mask;
    struct rsys_acl_get_mask_n_ia32_t acl_get_mask_n;
    struct rsys_acl_group_ia32_t acl_group;
    struct rsys_reg_ia32_t reg;
    struct rsys_jail_ia32_t jail;
    struct rsys_init_ia32_t init;
    struct rsys_um_auth_name_ia32_t um_auth_name;
    struct rsys_um_auth_uid_ia32_t um_auth_uid;
    struct rsys_um_add_user_ia32_t um_add_user;
    struct rsys_um_add_group_ia32_t um_add_group;
    struct rsys_um_add_gm_ia32_t um_add_gm;
    struct rsys_um_mod_user_ia32_t um_mod_user;
    struct rsys_um_mod_group_ia32_t um_mod_group;
    struct rsys_um_get_user_item_ia32_t um_get_user_item;
    struct rsys_um_get_group_item_ia32_t um_get_group_item;
    struct rsys_um_remove_user_ia32_t um_remove_user;
    struct rsys_um_remove_group_ia32_t um_remove_group;
    struct rsys_um_remove_gm_ia32_t um_remove_gm;
    struct rsys_um_user_exists_ia32_t um_user_exists;
    struct rsys_um_group_exists_ia32_t um_group_exists;
    struct rsys_um_get_next_user_ia32_t um_get_next_user;
    struct rsys_um_get_user_list_ia32_t um_get_user_list;
    struct rsys_um_get_gm_list_ia32_t um_get_gm_list;
    struct rsys_um_get_gm_user_list_ia32_t um_get_gm_user_list;
    struct rsys_um_get_group_list_ia32_t um_get_group_list;
    struct rsys_um_get_uid_ia32_t um_get_uid;
    struct rsys_um_get_gid_ia32_t um_get_gid;
    struct rsys_um_set_pass_ia32_t um_set_pass;
    struct rsys_um_set_pass_name_ia32_t um_set_pass_name;
    struct rsys_um_add_onetime_ia32_t um_add_onetime;
    struct rsys_um_add_onetime_name_ia32_t um_add_onetime_name;
    struct rsys_um_remove_all_onetime_ia32_t um_remove_all_onetime;
    struct rsys_um_remove_all_onetime_name_ia32_t um_remove_all_onetime_name;
    struct rsys_um_count_onetime_ia32_t um_count_onetime;
    struct rsys_um_count_onetime_name_ia32_t um_count_onetime_name;
    struct rsys_um_set_group_pass_ia32_t um_set_group_pass;
    struct rsys_um_check_account_ia32_t um_check_account;
    struct rsys_um_check_account_name_ia32_t um_check_account_name;
    struct rsys_um_get_max_history_ia32_t um_get_max_history;
    struct rsys_um_get_max_history_name_ia32_t um_get_max_history_name;
    struct rsys_um_set_max_history_ia32_t um_set_max_history;
    struct rsys_um_set_max_history_name_ia32_t um_set_max_history_name;
    struct rsys_list_ta_begin_ia32_t list_ta_begin;
    struct rsys_list_ta_begin_name_ia32_t list_ta_begin_name;
    struct rsys_list_ta_refresh_ia32_t list_ta_refresh;
    struct rsys_list_ta_commit_ia32_t list_ta_commit;
    struct rsys_list_ta_forget_ia32_t list_ta_forget;
    struct rsys_list_all_dev_ia32_t list_all_dev;
    struct rsys_acl_list_all_dev_ia32_t acl_list_all_dev;
    struct rsys_list_all_user_ia32_t list_all_user;
    struct rsys_acl_list_all_user_ia32_t acl_list_all_user;
    struct rsys_list_all_group_ia32_t list_all_group;
    struct rsys_acl_list_all_group_ia32_t acl_list_all_group;
    struct rsys_list_all_ipc_ia32_t list_all_ipc;
    struct rsys_rc_select_fd_create_type_ia32_t rc_select_fd_create_type;
    struct rsys_um_select_vset_ia32_t um_select_vset;
    struct rsys_um_add_user_hash_ia32_t um_add_user_hash;
    struct rsys_um_add_group_hash_ia32_t um_add_group_hash;
    struct rsys_um_set_pass_hash_ia32_t um_set_pass_hash;
    struct rsys_um_set_pass_name_hash_ia32_t um_set_pass_name_hash;
    struct rsys_um_set_group_pass_hash_ia32_t um_set_group_pass_hash;
    struct rsys_um_add_onetime_hash_ia32_t um_add_onetime_hash;
    struct rsys_um_add_onetime_name_hash_ia32_t um_add_onetime_name_hash;
    struct rsys_res_get_user_limit_ia32_t res_get_user_limit;
    struct rsys_res_set_user_limit_ia32_t res_set_user_limit;
    struct rsys_res_get_file_limit_ia32_t res_get_file_limit;
    struct rsys_res_set_file_limit_ia32_t res_set_file_limit;
    __u32 dummy;
  } __attribute__ ((aligned (4)));

#endif /* CONFIG_IA32_EMULATION || CONFIG_X86_X32 */

#endif
