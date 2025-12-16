/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2025:     */
/*   Amon Ott <ao@rsbac.org>     */
/* debug definitions             */
/* Last modified: 10/Jul/2025    */
/******************************* */

#ifndef __RSBAC_DEBUG_H
#define __RSBAC_DEBUG_H

#include <linux/init.h>
//#include <rsbac/types.h>

extern unsigned long int rsbac_flags;
extern void rsbac_flags_set(unsigned long int);

extern int rsbac_debug_no_write;

#ifdef CONFIG_RSBAC_DEBUG
extern int rsbac_debug_ds;
extern int rsbac_debug_write;
extern int rsbac_debug_memfd;
extern int rsbac_debug_stack;
extern int rsbac_debug_lists;
extern int rsbac_debug_aef;
#ifdef CONFIG_RSBAC_MPROTECT
extern int rsbac_debug_mprotect;
#endif
#endif

extern int rsbac_debug_adf_default;
extern rsbac_log_entry_t  rsbac_log_levels[R_NONE+1];

#define RSBAC_LOG_LEVELS_NAME "log_levels"
#define RSBAC_LOG_LEVEL_LIST_NAME "ll"
#define RSBAC_LOG_LEVEL_VERSION 5
#define RSBAC_LOG_LEVEL_OLD_VERSION 4
#define RSBAC_LOG_LEVEL_OLD_OLD_VERSION 3
#define RSBAC_LOG_LEVEL_KEY 13123231


extern int rsbac_no_defaults;

#ifdef CONFIG_RSBAC_INIT_DELAY
extern void rsbac_init_debug(void);
#else
extern void rsbac_init_debug(void) __init;
#endif

extern rsbac_boolean_t rsbac_parse_koptions(char *);

#define RSBAC_WAKEUP_KEY 'w'
#define RSBAC_WAKEUP_UKEY 'W'

#ifdef CONFIG_RSBAC_SOFTMODE
#define RSBAC_SOFTMODE_KEY 'x'
#define RSBAC_SOFTMODE_UKEY 'X'
extern int rsbac_softmode;
extern int rsbac_softmode_prohibit;
static inline int rsbac_in_softmode(void)
  {
    return rsbac_softmode;
  }
#ifdef CONFIG_RSBAC_SOFTMODE_IND
extern int  rsbac_ind_softmode[SW_NONE];
#endif
#endif

#if defined(CONFIG_RSBAC_FREEZE)
extern int rsbac_freeze;
#endif

extern int rsbac_list_recover;
extern int rsbac_list_noread;
extern u_int rsbac_list_auto_rehash_trigger;

#ifdef CONFIG_RSBAC_FD_CACHE
extern rsbac_time_t rsbac_fd_cache_ttl;
extern u_int rsbac_fd_cache_disable;
extern u_int rsbac_fd_cache_fuse;
extern u_int rsbac_fd_cache_ceph;
#endif

#ifdef CONFIG_RSBAC_UM
extern int rsbac_um_old_pw_unset_days;
#ifdef CONFIG_RSBAC_UM_NAME_CACHE
extern rsbac_time_t rsbac_um_name_cache_ttl;
extern u_int rsbac_um_name_cache_disable;
#endif
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE)
extern rsbac_time_t rsbac_list_check_interval;
#endif

#if defined(CONFIG_RSBAC_CAP_PROC_HIDE)
extern int rsbac_cap_process_hiding;
#endif
#if defined(CONFIG_RSBAC_CAP_FD_HIDE)
extern int rsbac_cap_fd_hiding;
#endif
#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
extern int rsbac_cap_log_missing;
#endif
#ifdef CONFIG_RSBAC_JAIL_LOG_MISSING
extern int rsbac_jail_log_missing;
#endif

#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
extern int rsbac_nosyslog;
#endif

#ifdef CONFIG_RSBAC_INIT_DELAY
extern int rsbac_no_delay_init;
extern rsbac_dev_t rsbac_delayed_root;
extern char rsbac_delayed_root_str[];
#endif

/* rsbac_printk(): You must always prepend the loglevel. As sequence numbers
 * are per rsbac_printk() message, it is strongly recommended to output single
 * full lines only.
 * Example:
 * rsbac_printk(KERN_DEBUG "Test value: %u\n", testval);
 */
extern int rsbac_printk(const char *, ...);

#ifdef CONFIG_RSBAC_DEBUG
#define rsbac_pr_debug(type, fmt, arg...) \
	do { if (rsbac_debug_##type) \
		rsbac_printk(KERN_DEBUG "%s(): " fmt, __FUNCTION__, ##arg); \
	} while (0)
#else
#define rsbac_pr_debug(type, fmt, arg...) do { } while (0)
#endif

#define rsbac_pr_get_error(attr) \
	do { rsbac_ds_get_error (__FUNCTION__, attr); \
	} while (0)
#define rsbac_pr_set_error(attr) \
	do { rsbac_ds_set_error (__FUNCTION__, attr); \
	} while (0)
#define rsbac_pr_get_error_num(attr, num) \
	do { rsbac_ds_get_error_num (__FUNCTION__, attr, num); \
	} while (0)
#define rsbac_pr_set_error_num(attr, num) \
	do { rsbac_ds_set_error_num (__FUNCTION__, attr, num); \
	} while (0)

#define rsbac_rc_pr_get_error(item) \
	do { rsbac_rc_ds_get_error (__FUNCTION__, item); \
	} while (0)
#define rsbac_rc_pr_set_error(item) \
	do { rsbac_rc_ds_set_error (__FUNCTION__, item); \
	} while (0)

#define RSBAC_LOG_MAXLINE 2020

#if defined(CONFIG_RSBAC_RMSG)
extern int rsbac_log(int, char *, int);

#define RSBAC_LOG_MAXREADBUF (rsbac_min(8192,RSBAC_MAX_KMALLOC))

struct rsbac_log_list_item_t {
	struct rsbac_log_list_item_t *next;
	u16 size;
	char * buffer;
};

struct rsbac_log_list_head_t {
	struct rsbac_log_list_item_t *head;
	struct rsbac_log_list_item_t *tail;
	u_int count;
	u_long lost;
};
#if defined(CONFIG_RSBAC_LOG_REMOTE)
extern rsbac_pid_t rsbaclogd_pid;
#endif
#endif

#ifdef CONFIG_RSBAC_NET
extern int rsbac_debug_ds_net;
extern int rsbac_debug_aef_net;
extern int rsbac_debug_adf_net;
#endif

extern void wakeup_rsbacd(u_long dummy);

/* switch log level for request */
void  rsbac_adf_log_switch(rsbac_adf_request_int_t request,
                           enum rsbac_target_t target,
                           rsbac_enum_t value);

int rsbac_get_adf_log(rsbac_adf_request_int_t request,
                      enum rsbac_target_t target,
                      u_int * value_p);

#ifdef CONFIG_RSBAC_DEBUG
#if defined(CONFIG_RSBAC_AUTO_WRITE)
extern int rsbac_debug_auto;
#endif /* CONFIG_RSBAC_AUTO_WRITE */

#ifdef CONFIG_RSBAC_FD_CACHE
extern int rsbac_debug_fdcache;
#endif

#if defined(CONFIG_RSBAC_MAC)
extern int rsbac_debug_ds_mac;
extern int rsbac_debug_aef_mac;
extern int rsbac_debug_adf_mac;
#endif

#if defined(CONFIG_RSBAC_RC)
extern int rsbac_debug_ds_rc;
extern int rsbac_debug_aef_rc;
extern int rsbac_debug_adf_rc;
#endif

#if defined(CONFIG_RSBAC_AUTH)
extern int rsbac_debug_ds_auth;
extern int rsbac_debug_aef_auth;
extern int rsbac_debug_adf_auth;
#endif

#if defined(CONFIG_RSBAC_REG)
extern int rsbac_debug_reg;
#endif

#if defined(CONFIG_RSBAC_ACL)
extern int rsbac_debug_ds_acl;
extern int rsbac_debug_aef_acl;
extern int rsbac_debug_adf_acl;
#endif

#if defined(CONFIG_RSBAC_CAP)
extern int rsbac_debug_adf_cap;
#endif

#if defined(CONFIG_RSBAC_JAIL)
extern int rsbac_debug_aef_jail;
extern int rsbac_debug_adf_jail;
#endif

#if defined(CONFIG_RSBAC_RES)
extern int rsbac_debug_adf_res;
#endif

#if defined(CONFIG_RSBAC_UM)
extern int rsbac_debug_ds_um;
extern int rsbac_debug_aef_um;
extern int rsbac_debug_adf_um;
#endif

#if defined(CONFIG_RSBAC_UDF)
extern int rsbac_debug_adf_udf;
#endif

#endif /* DEBUG */

extern int rsbac_memfd_keep;

#if defined(CONFIG_RSBAC_UM_EXCL)
extern int rsbac_um_no_excl;
#endif

#if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
extern int rsbac_auth_enable_login;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
extern int rsbac_auth_learn;
#define RSBAC_AUTH_LEARN_TA_NAME "AUTH-learn"
#endif
#endif

#if defined(CONFIG_RSBAC_RC_LEARN)
extern int rsbac_rc_learn;
#define RSBAC_RC_LEARN_TA_NAME "RC-learn"
#endif

#if defined(CONFIG_RSBAC_RC)
extern int rsbac_rc_force_ipc_type;
#endif

#if defined(CONFIG_RSBAC_CAP_LEARN)
extern int rsbac_cap_learn;
#define RSBAC_CAP_LEARN_TA_NAME "CAP-learn"
#endif

#if defined(CONFIG_RSBAC_ACL_LEARN)
extern int rsbac_acl_learn_fd;
#define RSBAC_ACL_LEARN_TA_NAME "ACL-FD-learn"
#endif

#endif
