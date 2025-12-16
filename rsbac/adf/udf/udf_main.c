/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - User Space Decision Facility     */
/* File: rsbac/adf/udf/udf_main.c                    */
/*                                                   */
/* Author and (c) 1999-2024: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 13/Dec/2024                        */
/*************************************************** */

#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/kmod.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf.h>
#include <rsbac/lists.h>
#include <rsbac/udf.h>
#include <rsbac/adf_main.h>
#include <rsbac/debug.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/proc_fs.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

#define UDF_MAX_PROGNAME PATH_MAX

static char udf_checker_prog[RSBAC_MAXNAMELEN] = "";

static int R_INIT udf_checker_setup(char *line)
  {
    strncpy(udf_checker_prog, line, RSBAC_MAXNAMELEN - 1);
    udf_checker_prog[RSBAC_MAXNAMELEN - 1] = 0;
    return 1;
  }
__setup("rsbac_udf_checker=", udf_checker_setup);

static int udf_checker_wait = UMH_WAIT_PROC | UMH_KILLABLE;

static int R_INIT udf_checker_wait_setup(char *line)
  {
    udf_checker_wait = UMH_WAIT_PROC;
    return 1;
  }
__setup("rsbac_udf_nokill", udf_checker_wait_setup);

#if defined(CONFIG_RSBAC_UDF_CACHE)
static rsbac_time_t rsbac_udf_ttl = CONFIG_RSBAC_UDF_TTL;
static rsbac_time_t rsbac_udf_progress_ttl = CONFIG_RSBAC_UDF_PROGRESS_TTL;
#endif

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
#ifndef PROC_BLOCK_SIZE
#define PROC_BLOCK_SIZE	(3*1024)  /* 4K page size but our output routines use some slack for overruns */
#endif

EXPORT_SYMBOL(rsbac_udf_get_ttl);
/* Get ttl for new cache items in seconds */
rsbac_time_t rsbac_udf_get_ttl(void)
{
#if defined(CONFIG_RSBAC_UDF_CACHE)
	return rsbac_udf_ttl;
#else
	return 0;
#endif
}

EXPORT_SYMBOL(rsbac_udf_set_ttl);
void rsbac_udf_set_ttl(rsbac_time_t ttl)
{
#if defined(CONFIG_RSBAC_UDF_CACHE)
	if (ttl) {
		if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
			ttl = RSBAC_LIST_MAX_AGE_LIMIT;
		rsbac_udf_ttl = ttl;
	}
#endif
}

EXPORT_SYMBOL(rsbac_udf_get_progress_ttl);
/* Get ttl for in-progress marker in seconds */
rsbac_time_t rsbac_udf_get_progress_ttl(void)
{
#if defined(CONFIG_RSBAC_UDF_CACHE)
	return rsbac_udf_progress_ttl;
#else
	return 0;
#endif
}

EXPORT_SYMBOL(rsbac_udf_set_progress_ttl);
void rsbac_udf_set_progress_ttl(rsbac_time_t ttl)
{
#if defined(CONFIG_RSBAC_UDF_CACHE)
	if (ttl) {
		if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
			ttl = RSBAC_LIST_MAX_AGE_LIMIT;
		rsbac_udf_progress_ttl = ttl;
	}
#endif
}

static int
udf_checker_proc_show(struct seq_file *m, void *v)
{
  union rsbac_target_id_t       rsbac_target_id;
  union rsbac_attribute_value_t rsbac_attribute_value;

  if (!rsbac_is_initialized())
    return (-ENOSYS);

#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "udf_checker_proc_info(): calling ADF.\n");
    }
#endif
  rsbac_target_id.scd = ST_rsbac;
  rsbac_attribute_value.dummy = 0;
  if (!rsbac_adf_request(R_GET_STATUS_DATA,
			 task_pid(current),
			 T_SCD,
			 rsbac_target_id,
			 A_none,
			 rsbac_attribute_value))
    {
      return -EPERM;
    }

  seq_printf(m, "%s\n", udf_checker_prog);

  return 0;
}

static ssize_t udf_checker_proc_write(struct file * file, const char __user * buf,
				     size_t count, loff_t *ppos)
{
    ssize_t err;
    char * k_buf;
    char * p;

    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(count > RSBAC_MAXNAMELEN - 1) {
	return -EOVERFLOW;
    }

    if (!rsbac_is_initialized()) {
      return -ENOSYS;
    }

    if (!(k_buf = (char *) __get_free_page(GFP_KERNEL)))
      return -ENOMEM;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef) {
      rsbac_printk(KERN_DEBUG "udf_checker_proc_write(): calling ADF.\n");
    }
#endif
    rsbac_target_id.dummy = 0;
    rsbac_attribute_value.switch_target = SW_UDF;
    if (!rsbac_adf_request(R_SWITCH_MODULE,
			   task_pid(current),
			   T_NONE,
			   rsbac_target_id,
			   A_switch_target,
			   rsbac_attribute_value)) {
       err = -EPERM;
       goto out;
    }

    /*
     * Usage: echo "/path/to/program" > /proc/rsbac_info/udf_checker
     *   to set checker program to given value and enable checking
     *   Program gets called with single parameter "path to file"
     *   and must exit with either 0 (allowed) or another value (denied)
     */
    err = copy_from_user(k_buf, buf, count);
    if(err < 0)
      return err;
    k_buf[RSBAC_MAXNAMELEN - 1] = 0;
    p = k_buf;
    if (*p && (*p != '/') && (*p != '\n')) {
      err = -EINVAL;
      goto out;
    }
    while (*p && (*p != '\n')) {
      if (! (   ((*p >= 'A') && (*p <= 'Z'))
	     || ((*p >= 'a') && (*p <= 'z'))
	     || ((*p >= '0') && (*p <= '9'))
	     || (*p == '/')
	     || (*p == '_')
	     || (*p == '-')
	     || (*p == '.')
	    )
	 ) {
        rsbac_printk(KERN_INFO
		     "udf_checker_proc_write(): setting UDF checker denied, invalid character detected.\n");
	err = -EINVAL;
	goto out;
      }
      p++;
    }
    if (*p)
      *p = 0;

    strncpy(udf_checker_prog, k_buf, RSBAC_MAXNAMELEN - 1);
    udf_checker_prog[RSBAC_MAXNAMELEN - 1] = 0;
    if (udf_checker_prog[0])
      rsbac_printk(KERN_INFO
		   "udf_checker_proc_write(): setting UDF checker to %s, checking is now enabled\n",
		   udf_checker_prog);
    else
      rsbac_printk(KERN_INFO
		   "udf_checker_proc_write(): UDF checker set to empty, checking is now disabled\n",
		   udf_checker_prog);
    err = count;

out:
  free_page((ulong) k_buf);
  return err;
  }

static int udf_checker_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, udf_checker_proc_show, NULL);
}

static const struct proc_ops udf_checker_proc_ops = {
       .proc_open	= udf_checker_proc_open,
       .proc_read	= seq_read,
       .proc_write	= udf_checker_proc_write,
       .proc_lseek	= seq_lseek,
       .proc_release	= single_release,
};

static struct proc_dir_entry *udf_checker;

#endif /* CONFIG_RSBAC_PROC */

#if defined(CONFIG_RSBAC_UDF_CACHE)
static int udf_reset_checked(struct rsbac_fs_file_t file)
{
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_target_id_t       i_tid;

	/* reset checked status for file */
	rsbac_pr_debug(adf_udf, "pid %u(%s), resetting checked status.\n",
				       current->pid, current->comm);
	i_tid.file=file;
	i_attr_val1.udf_checked = UDF_unchecked;
	if(rsbac_ta_set_attr_ttl(0,
				SW_UDF,
				T_FILE,
				i_tid,
				A_udf_checked,
				i_attr_val1,
				0))
	{
		rsbac_printk(KERN_WARNING "udf_reset_checked(): rsbac_set_attr() for udf_checked on device %02u:%02u inode %lu returned error!\n",
			MAJOR(file.device), MINOR(file.device), file.inode);
		return -RSBAC_EWRITEFAILED;
	}
	if (rsbac_get_attr(SW_UDF,
		T_FILE,
		i_tid,
		A_udf_checker,
		&i_attr_val1,
		TRUE)) {
		rsbac_printk(KERN_WARNING
			"udf_reset_checked(): rsbac_get_attr() for udf_checker returned error!\n");
		return -RSBAC_EREADFAILED;
	}
	if (i_attr_val1.udf_checker) {
		/* reset checker flag for file */
		i_attr_val1.udf_checker = FALSE;
		if(rsbac_set_attr(SW_UDF,
					T_FILE,
					i_tid,
					A_udf_checker,
					i_attr_val1))
		{
			rsbac_printk(KERN_WARNING "udf_reset_checked(): rsbac_set_attr() for udf_checker on device %02u:%02u inode %lu returned error!\n",
				MAJOR(file.device), MINOR(file.device), file.inode);
			return -RSBAC_EWRITEFAILED;
		}
	}
	return 0;
}
#else
static inline int udf_reset_checked(struct rsbac_fs_file_t file)
{
	return 0;
}
#endif

static enum rsbac_adf_req_ret_t udf_do_check(union rsbac_target_id_t tid)
{
	char *envp[] = { "HOME=/",
			"TERM=linux",
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
			NULL };
	char *argv[] = {udf_checker_prog, NULL, NULL };
	char * progname;
	int err;
	u_int result;
#if defined(CONFIG_RSBAC_UDF_CACHE)
	union rsbac_attribute_value_t i_attr_val1;
#endif

	progname = rsbac_kmalloc_unlocked(RSBAC_UDF_PATH_MAX);
	if (!progname) {
		rsbac_printk(KERN_WARNING
			"%s(): cannot allocate memory!\n", __FUNCTION__);
		return NOT_GRANTED;
	}

	err = rsbac_lookup_full_path(tid.file.dentry_p, progname, RSBAC_UDF_PATH_MAX, 0);
	if (err < 0) {
		char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING
				"%s(): rsbac_lookup_full_path() returned error %s!\n", __FUNCTION__, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
		return NOT_GRANTED;
	}

#if defined(CONFIG_RSBAC_UDF_CACHE)
       i_attr_val1.udf_checked = UDF_in_progress;
       if (rsbac_ta_set_attr_ttl(0,
				SW_UDF,
				T_FILE,
				tid,
				A_udf_checked,
				i_attr_val1,
				rsbac_udf_progress_ttl))
	rsbac_printk(KERN_WARNING "%s():%u: rsbac_ta_set_attr_ttl() returned error!\n",__FUNCTION__,  __LINE__);
#endif

	rsbac_pr_debug(adf_udf, "calling %s for path %s.", udf_checker_prog, progname);

	argv[1] = progname;
	err = call_usermodehelper(argv[0], argv, envp, udf_checker_wait);
	rsbac_kfree(progname);
	result = err >> 8;

	if (err < 0) {
		if (err != -ERESTARTSYS)
			rsbac_printk(KERN_WARNING "%s(): call_usermodehelper() could not execute %s, error %i.\n", __FUNCTION__, udf_checker_prog, err);
#if defined(CONFIG_RSBAC_DEBUG)
		else
			rsbac_pr_debug(adf_udf, "call_usermodehelper() returned -ERESTARTSYS, checker was interrupted.\n");
#endif
#if defined(CONFIG_RSBAC_UDF_CACHE)
		i_attr_val1.udf_checked = UDF_unchecked;
		if (rsbac_ta_set_attr_ttl(0,
				SW_UDF,
				T_FILE,
				tid,
				A_udf_checked,
				i_attr_val1,
				0))
			rsbac_printk(KERN_WARNING "%s():%u: rsbac_set_attr() returned error!\n", __FUNCTION__, __LINE__);
#endif
	}
#if defined(CONFIG_RSBAC_DEBUG) || defined(CONFIG_RSBAC_UDF_CACHE)
	else {
		u_int signal;

		signal = err & 255;
		rsbac_pr_debug(adf_udf, "call_usermodehelper() returned %u (result %u, signal %u).\n", err, result, signal);
#if defined(CONFIG_RSBAC_UDF_CACHE)
		/* only cache, if not killed by signal and no temp fail */
		if (   !signal
		    && (result != UDF_res_temp_fail_allow)
		    && (result != UDF_res_temp_fail_deny)
		   ) {
			if(!result)
				i_attr_val1.udf_checked = UDF_allowed;
			else
				i_attr_val1.udf_checked = UDF_denied;
			if (rsbac_ta_set_attr_ttl(0,
					SW_UDF,
					T_FILE,
					tid,
					A_udf_checked,
					i_attr_val1,
					rsbac_udf_ttl))
				rsbac_printk(KERN_WARNING "%s():%u: rsbac_ta_set_attr_ttl() returned error!\n",__FUNCTION__,  __LINE__);
		} else {
			/* reset to unchecked, because current value is in_progress */
			i_attr_val1.udf_checked = UDF_unchecked;
			if (rsbac_ta_set_attr_ttl(0,
					SW_UDF,
					T_FILE,
					tid,
					A_udf_checked,
					i_attr_val1,
					0))
				rsbac_printk(KERN_WARNING "%s():%u: rsbac_set_attr() returned error!\n", __FUNCTION__, __LINE__);
		}
#endif
	}
#endif

	if (!err || (result == UDF_res_temp_fail_allow))
		return GRANTED;
	else
		return NOT_GRANTED;
}

static int udf_ignored(rsbac_pid_t caller_pid, union rsbac_target_id_t tid)
{
	union rsbac_attribute_value_t i_attr_val1;

	if (rsbac_get_attr(SW_UDF,
		T_FILE,
		tid,
		A_udf_do_check,
		&i_attr_val1,
		TRUE)) {
		rsbac_printk(KERN_WARNING
			"rsbac_adf_request_udf(): rsbac_get_attr() for udf_do_check returned error!\n");
		return FALSE;
	}
	if(i_attr_val1.udf_do_check == UDF_never)
		return TRUE;
#ifdef CONFIG_RSBAC_NET_OBJ
	if(i_attr_val1.udf_do_check == UDF_remoteonly) {
		tid.process = caller_pid;
		if (rsbac_get_attr(SW_GEN,
			T_PROCESS,
			tid,
			A_remote_ip,
			&i_attr_val1,
			FALSE)) {
			rsbac_printk(KERN_WARNING
				"rsbac_adf_request_udf(): rsbac_get_attr() for remote_ip returned error!\n");
			return FALSE;
		}
		if (i_attr_val1.remote_ip)
			return FALSE;
		else
			return TRUE;
	}
#endif
	return FALSE;
}

#if defined(CONFIG_RSBAC_UDF_UDF_PROT)
static enum rsbac_adf_req_ret_t udf_check_secoff(rsbac_uid_t owner, enum rsbac_attribute_t attr, int readonly)
{
	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	/* Security Officer? */
	i_tid.user = owner;
	if (rsbac_get_attr(SW_UDF,
			T_USER,
			i_tid,
			A_udf_role,
			&i_attr_val1,
			TRUE)) {
			rsbac_printk(KERN_WARNING
					"rsbac_adf_request_udf(): rsbac_get_attr() returned error!\n");
			return NOT_GRANTED;
	}
	/* if sec_officer, then grant */
	if (   (i_attr_val1.system_role == SR_security_officer)
	    || (readonly && (i_attr_val1.system_role == SR_administrator))
	   )
		return GRANTED;
	else
		return NOT_GRANTED;
}
#endif

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_udf(void)
#else
int __init rsbac_init_udf(void)
#endif
{
	if (rsbac_is_initialized())
	{
		rsbac_printk(KERN_WARNING "rsbac_init_udf(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	/* init data structures */
	rsbac_printk(KERN_INFO "rsbac_init_udf(): Initializing RSBAC: UDF subsystem\n");
	if (udf_checker_prog[0])
		rsbac_printk(KERN_DEBUG "rsbac_init_udf(): rsbac_udf_checker is %s\n", udf_checker_prog);
	else
		rsbac_printk(KERN_DEBUG "rsbac_init_udf(): rsbac_udf_checker is unset, no checking\n");

	if (udf_checker_wait & UMH_KILLABLE)
		rsbac_printk(KERN_DEBUG "rsbac_init_udf(): rsbac_udf_nokill is not set, checker is killable\n");
	else
		rsbac_printk(KERN_DEBUG "rsbac_init_udf(): rsbac_udf_nokill is set, checker is not killable\n");

	#if defined(CONFIG_RSBAC_PROC)
	udf_checker = proc_create("udf_checker", S_IFREG | S_IRUGO | S_IWUGO, proc_rsbac_root_p, &udf_checker_proc_ops);
	#endif

	return 0;
}

inline enum rsbac_adf_req_ret_t
rsbac_adf_request_udf (enum  rsbac_adf_request_t     request,
		rsbac_pid_t                   caller_pid,
		enum  rsbac_target_t          target,
		union rsbac_target_id_t       tid,
		enum  rsbac_attribute_t       attr,
		union rsbac_attribute_value_t attr_val,
		rsbac_uid_t             owner)
{
	int daemon_allowed;

	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	/* get udf_do_check for target */
	switch(target) {
		case T_FILE:
			switch(request) {
				case R_EXECUTE:
					if(udf_ignored(caller_pid, tid))
						return DO_NOT_CARE;
					daemon_allowed = 0;
					break;
				case R_READ_WRITE_OPEN:
				case R_READ_OPEN:
					if(udf_ignored(caller_pid, tid))
						return DO_NOT_CARE;
					daemon_allowed = 1;
					break;
#if defined(CONFIG_RSBAC_UDF_UDF_PROT)
				case R_READ_ATTRIBUTE:
					switch (attr) {
						case A_udf_role:
						case A_udf_checker:
						case A_udf_checked:
						case A_udf_do_check:
						case A_system_role:
						case A_none:
							return udf_check_secoff(owner, attr, TRUE);
						default:
							return DO_NOT_CARE;
					}
				case R_MODIFY_ATTRIBUTE:
					switch (attr) {
						case A_udf_role:
						case A_udf_checker:
						case A_udf_do_check:
						case A_system_role:
						case A_none:
							return udf_check_secoff(owner, attr, FALSE);
						case A_udf_checked:
							if (attr_val.udf_checked == UDF_in_progress)
								return NOT_GRANTED;
							return udf_check_secoff(owner, attr, FALSE);
						default:
							return DO_NOT_CARE;
					}
#endif
				default:
					return DO_NOT_CARE;
			}
			break;

#if defined(CONFIG_RSBAC_UDF_UDF_PROT)
		case T_DIR:
		case T_PROCESS:
		case T_USER:
			switch(request) {
				case R_READ_ATTRIBUTE:
					switch (attr) {
						case A_udf_role:
						case A_udf_checker:
						case A_udf_checked:
						case A_udf_do_check:
						case A_system_role:
						case A_none:
							return udf_check_secoff(owner, attr, TRUE);
						default:
							return DO_NOT_CARE;
					}
				case R_MODIFY_ATTRIBUTE:
					switch (attr) {
						case A_udf_role:
						case A_udf_checker:
						case A_udf_do_check:
						case A_system_role:
						case A_none:
							return udf_check_secoff(owner, attr, FALSE);
						case A_udf_checked:
							if (attr_val.udf_checked == UDF_in_progress)
								return NOT_GRANTED;
							return udf_check_secoff(owner, attr, FALSE);
						default:
							return DO_NOT_CARE;
					}
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_NONE:
			switch(request) {
				case R_SWITCH_MODULE:
					/* we need the switch_target */
					if(attr != A_switch_target)
						return NOT_GRANTED;
					/* do not care for other modules */
					if(   (attr_val.switch_target != SW_UDF)
#ifdef CONFIG_RSBAC_SOFTMODE
						&& (attr_val.switch_target != SW_SOFTMODE)
#endif
#ifdef CONFIG_RSBAC_FREEZE
						&& (attr_val.switch_target != SW_FREEZE)
#endif
#ifdef CONFIG_RSBAC_MPROTECT
						&& (attr_val.switch_target != SW_MPROTECT)
#endif
					  )
						return DO_NOT_CARE;
					return udf_check_secoff(owner, attr, FALSE);
				default:
					return DO_NOT_CARE;
			}
			break;
#endif /* UDF_UDF_PROT */

		default:
			return DO_NOT_CARE;
	}

/* From here we can only have FILE targets */

/* checker enabled? */
	if (!udf_checker_prog[0]) {
		rsbac_pr_debug(adf_udf, "pid %u(%s), no checker defined.\n",
				current->pid, current->comm);
		return DO_NOT_CARE;
	}

	if (daemon_allowed) {
		i_tid.process = caller_pid;
		if (rsbac_get_attr(SW_UDF,
					T_PROCESS,
					i_tid,
					A_udf_checker,
					&i_attr_val1,
					FALSE)) {
			rsbac_printk(KERN_WARNING
					"rsbac_adf_request_udf(): rsbac_get_attr() returned error!\n");
			return NOT_GRANTED;
		}
		/* if checker, then grant */
		if (i_attr_val1.udf_checker) {
			rsbac_pr_debug(adf_udf, "pid %u(%s) is a checker, no checking required for device %02u:%02u inode %lu.\n",
					current->pid, current->comm,
					RSBAC_MAJOR(tid.file.device),
					RSBAC_MINOR(tid.file.device),
					tid.file.inode);
			return GRANTED;
		}
	}

#if defined(CONFIG_RSBAC_UDF_CACHE)
	/* Other check in progress? This is no dead loop, because
	 * udf_checked == UDF_in_progress always has a ttl
	 */
	while (1) {
		if (rsbac_get_attr(SW_UDF,
				target,
				tid,
				A_udf_checked,
				&i_attr_val1,
				FALSE)) {
			rsbac_printk(KERN_WARNING
					"rsbac_adf_request_udf(): rsbac_get_attr() returned error!\n");
			return NOT_GRANTED;
		}
		if (i_attr_val1.udf_checked != UDF_in_progress)
			break;
		rsbac_pr_debug(adf_udf, "pid %u(%s): check for device %02u:%02u inode %lu is in progress, wait 500ms",
					current->pid, current->comm,
					RSBAC_MAJOR(tid.file.device),
					RSBAC_MINOR(tid.file.device),
					tid.file.inode);
		msleep_interruptible(500);
	}
	if(i_attr_val1.udf_checked == UDF_allowed) {
		rsbac_pr_debug(adf_udf, "pid %u(%s), result allowed for device %02u:%02u inode %lu taken from cache.\n",
				current->pid, current->comm,
				RSBAC_MAJOR(tid.file.device),
				RSBAC_MINOR(tid.file.device),
				tid.file.inode);
		return GRANTED;
	}
	if(i_attr_val1.udf_checked == UDF_denied) {
		rsbac_pr_debug(adf_udf, "pid %u(%s), result denied for device %02u:%02u inode %lu taken from cache.\n",
				current->pid, current->comm,
				RSBAC_MAJOR(tid.file.device),
				RSBAC_MINOR(tid.file.device),
				tid.file.inode);
		return NOT_GRANTED;
	}
#endif

	rsbac_pr_debug(adf_udf, "pid %u(%s), checking required for device %02u:%02u inode %lu.\n",
			current->pid, current->comm,
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device),
			tid.file.inode);
	/* call checker */
	return udf_do_check(tid);
} /* end of rsbac_adf_request_udf() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up. Because of this, the write boundary is not adjusted - there  */
/* is no user-level writing anyway...                                        */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

inline int rsbac_adf_set_attr_udf(
		enum  rsbac_adf_request_t     request,
		rsbac_pid_t                   caller_pid,
		enum  rsbac_target_t          target,
		union rsbac_target_id_t       tid,
		enum  rsbac_target_t          new_target,
		union rsbac_target_id_t       new_tid,
		enum  rsbac_attribute_t       attr,
		union rsbac_attribute_value_t attr_val,
		rsbac_uid_t             owner)
{
	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	switch(target) {
		case T_FILE:
			switch(request) {
				case R_EXECUTE:
					/* get udf_checker for file */
					if (rsbac_get_attr(SW_UDF,
								T_FILE,
								tid,
								A_udf_checker,
								&i_attr_val1,
								TRUE)) {
						rsbac_printk(KERN_WARNING
								"rsbac_adf_set_attr_udf(): rsbac_get_attr() returned error!\n");
						return -RSBAC_EREADFAILED;
					}
					/* and set for process, if new program is checker */
					if(i_attr_val1.udf_checker) {
						i_tid.process = caller_pid;
						if (rsbac_set_attr(SW_UDF,
								T_PROCESS,
								i_tid,
								A_udf_checker,
								i_attr_val1)) {
							rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_udf(): rsbac_set_attr() returned error!\n");
							return -RSBAC_EWRITEFAILED;
						}
					}
					return 0;
				case R_CLOSE:
					if(udf_ignored(caller_pid, tid))
						return 0;
					if(   (attr == A_f_mode)
						&& (attr_val.f_mode & FMODE_WRITE)
					) {
						udf_reset_checked(tid.file);
#if defined(CONFIG_RSBAC_UDF_ON_CLOSE)
						break;
#endif
					}
					return 0;
				case R_APPEND_OPEN:
				case R_READ_WRITE_OPEN:
				case R_WRITE_OPEN:
					if(!udf_ignored(caller_pid, tid))
						udf_reset_checked(tid.file);
					return 0;
				case R_DELETE:
					if(!udf_ignored(caller_pid, tid))
						udf_reset_checked(tid.file);
					return 0;
				default:
					return 0;
			}
			break;
		case T_PROCESS:
			switch(request) {
				case R_CLONE:
					/* Get udf_checker from first process */
					if (rsbac_get_attr(SW_UDF,
							T_PROCESS,
							tid,
							A_udf_checker,
							&i_attr_val1,
							FALSE)) {
						rsbac_printk(KERN_WARNING
							"rsbac_adf_set_attr_udf(): rsbac_get_attr() returned error!\n");
						return -RSBAC_EREADFAILED;
					}
					/* Set udf_checker for new process, if set for first */
					if (   i_attr_val1.udf_checker
						&& (rsbac_set_attr(SW_UDF,
								T_PROCESS,
								new_tid,
								A_udf_checker,
								i_attr_val1)) ) {
						rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_udf(): rsbac_set_attr() returned error!\n");
						return -RSBAC_EWRITEFAILED;
					}
					return 0;
				default:
					return 0;
			}
		default:
			return 0;
	}

/* only needed for CLOSE, if enabled */
#if defined(CONFIG_RSBAC_UDF_ON_CLOSE)
/* checker enabled? */
	if (!udf_checker_prog[0])
		return 0;

	i_tid.process = caller_pid;
	if (rsbac_get_attr(SW_UDF,
				T_PROCESS,
				i_tid,
				A_udf_checker,
				&i_attr_val1,
				FALSE)) {
		rsbac_printk(KERN_WARNING
				"rsbac_adf_set_attr_udf(): rsbac_get_attr() returned error!\n");
		return -RSBAC_EREADFAILED;
	}
	/* if checker, then grant */
	if (i_attr_val1.udf_checker) {
		rsbac_pr_debug(adf_udf, "pid %u(%s) is a checker, no checking required for device %02u:%02u inode %lu.\n",
				current->pid, current->comm,
				RSBAC_MAJOR(tid.file.device),
				RSBAC_MINOR(tid.file.device),
				tid.file.inode);
		return 0;
	}

#if defined(CONFIG_RSBAC_UDF_CACHE)
	/* Other check in progress? This is no dead loop, because
	 * udf_checked == UDF_in_progress always has a ttl
	 */
	while (1) {
		if (rsbac_get_attr(SW_UDF,
				target,
				tid,
				A_udf_checked,
				&i_attr_val1,
				FALSE)) {
			rsbac_printk(KERN_WARNING
					"rsbac_adf_request_udf(): rsbac_get_attr() returned error!\n");
			return -RSBAC_EREADFAILED;
		}
		if (i_attr_val1.udf_checked != UDF_in_progress)
			break;
		rsbac_pr_debug(adf_udf, "pid %u(%s): check for device %02u:%02u inode %lu is in progress, wait 500ms",
					current->pid, current->comm,
					RSBAC_MAJOR(tid.file.device),
					RSBAC_MINOR(tid.file.device),
					tid.file.inode);
		msleep_interruptible(500);
	}
	if(i_attr_val1.udf_checked == UDF_allowed) {
		rsbac_pr_debug(adf_udf, "pid %u(%s), result allowed for device %02u:%02u inode %lu taken from cache.\n",
				current->pid, current->comm,
				RSBAC_MAJOR(tid.file.device),
				RSBAC_MINOR(tid.file.device),
				tid.file.inode);
		return 0;
	}
	if(i_attr_val1.udf_checked == UDF_denied) {
		rsbac_pr_debug(adf_udf, "pid %u(%s), result denied for device %02u:%02u inode %lu taken from cache.\n",
				current->pid, current->comm,
				RSBAC_MAJOR(tid.file.device),
				RSBAC_MINOR(tid.file.device),
				tid.file.inode);
		return 0;
	}
#endif

	rsbac_pr_debug(adf_udf, "pid %u(%s), checking required for device %02u:%02u inode %lu.\n",
			current->pid, current->comm,
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device),
			tid.file.inode);
	/* call checker */
	udf_do_check(tid);
#endif /* RSBAC_UDF_ON_CLOSE */

	return 0;
} /* end of rsbac_adf_set_attr_udf() */
