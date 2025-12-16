/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2024:     */
/*   Amon Ott <ao@rsbac.org>     */
/* API: Data structures          */
/* and functions for Access      */
/* Control Information / RC      */
/* Last modified: 13/Dec/2024    */
/******************************* */

#ifndef __RSBAC_RC_H
#define __RSBAC_RC_H

#include <linux/init.h>
#include <rsbac/rc_types.h>

/***************************************************/
/*               General Prototypes                */
/***************************************************/

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac_error.h.                 */

/****************************************************************************/
/* Initialization, including ACI restoration for all mounted devices from   */
/* disk. After this call, all ACI is kept in memory for performance reasons.*/

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_rc(void);
#else
int rsbac_init_rc(void) __init;
#endif

/* Find the boot role */
#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_rc_get_boot_role(rsbac_rc_role_id_t * role_p);
#else
int rsbac_rc_get_boot_role(rsbac_rc_role_id_t * role_p) __init;
#endif

/* Some information about the current status is also available              */

int rsbac_stats_rc(void);

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the spinlocks to protect the targets during  */
/* access.                                                                  */

/* All roles are always there, so instead of creation, we supply a copy for */
/* initialization. There is always the well-defined role general to copy    */
int rsbac_rc_copy_role(rsbac_list_ta_number_t ta_number,
		       rsbac_rc_role_id_t from_role,
		       rsbac_rc_role_id_t to_role);

int rsbac_rc_copy_type(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       rsbac_rc_type_id_t from_type,
		       rsbac_rc_type_id_t to_type);

/* Getting item values */
int rsbac_rc_get_item(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      union rsbac_rc_target_id_t subtid,
		      enum rsbac_rc_item_t item,
		      union rsbac_rc_item_value_t *value_p,
		      rsbac_time_t * ttl_p);

/* Setting item values */
int rsbac_rc_set_item(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      union rsbac_rc_target_id_t subtid,
		      enum rsbac_rc_item_t item,
		      union rsbac_rc_item_value_t value, rsbac_time_t ttl);

/* Checking role's compatibility */
rsbac_boolean_t rsbac_rc_check_comp(rsbac_rc_role_id_t role,
				    union rsbac_rc_target_id_t subtid,
				    enum rsbac_rc_item_t item,
				    enum rsbac_rc_special_rights_t right);

#ifdef CONFIG_RSBAC_RC_FORCE_LOG
/* Checking role to type log settings */
rsbac_boolean_t rsbac_rc_check_log(rsbac_rc_role_id_t role,
				   rsbac_rc_type_id_t type,
				   enum rsbac_rc_item_t item,
				   enum rsbac_rc_special_rights_t right,
				   enum rsbac_rc_log_t log_type);
#endif

/* Checking whether role exists */
rsbac_boolean_t rsbac_rc_role_exists(rsbac_list_ta_number_t ta_number,
				     rsbac_rc_role_id_t role);

rsbac_boolean_t rsbac_rc_type_exists(rsbac_list_ta_number_t ta_number,
				     enum rsbac_target_t target,
				     rsbac_rc_type_id_t type);

/* Get list of defined items. Returns number or negative error.
 * Allocates array via rsbac_kmalloc, if number > 0 - rsbac_kfree after use! */
int rsbac_rc_get_list(rsbac_list_ta_number_t ta_number,
		      enum rsbac_rc_target_t target,
		      union rsbac_rc_target_id_t tid,
		      enum rsbac_rc_item_t item,
		      __u32 ** array_pp, rsbac_time_t ** ttl_array_pp);

int rsbac_rc_select_fd_create_type(rsbac_rc_type_id_t type);

int rsbac_rc_test_admin_roles(rsbac_rc_role_id_t t_role,
                              rsbac_boolean_t modify);

int rsbac_rc_test_role_admin(rsbac_boolean_t modify);

enum rsbac_adf_req_ret_t
rsbac_rc_check_type_comp(enum rsbac_target_t target,
                         rsbac_rc_type_id_t type,
                         enum rsbac_rc_special_rights_t request,
                         rsbac_pid_t caller_pid);

#endif
