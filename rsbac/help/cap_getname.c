/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 1999-2023:        */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for CAP module */
/* Last modified: 18/Dec/2023       */
/********************************** */

#include <rsbac/getname.h>
#include <rsbac/cap_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#include <rsbac/aci.h>
#include <rsbac/lists.h>
#if defined(CONFIG_RSBAC_CAP_LEARN)
#include <linux/file.h>
#endif

/*****************************************/

#ifdef CONFIG_RSBAC_CAP_LEARN_TA
rsbac_list_ta_number_t cap_learn_ta = CONFIG_RSBAC_CAP_LEARN_TA;
#else
#define cap_learn_ta 0
#endif

#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
bool rsbac_cap_log_missing_cap(int cap)
  {
    char * tmp;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    rsbac_cap_vector_t            i_cap_vector;
    bool                          res = false;

    i_cap_vector = BIT_ULL(cap);

#ifdef CONFIG_RSBAC_CAP_LEARN_TA
    if (!rsbac_list_ta_exist(cap_learn_ta))
	rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
                &cap_learn_ta,
		RSBAC_ALL_USERS,
		RSBAC_CAP_LEARN_TA_NAME,
		NULL);
#endif
    i_tid.process = task_pid(current);
    if (rsbac_ta_get_attr(cap_learn_ta,
                       SW_CAP,
                       T_PROCESS,
                       i_tid,
                       A_max_caps_user,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_cap_log_missing_cap()", A_max_caps_user);
      }
    else
      {
        if(!(i_attr_val1.max_caps_user & i_cap_vector))
          {
#if defined(CONFIG_RSBAC_CAP_LEARN)
            if (rsbac_cap_learn)
              {
                tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                if(tmp)
                  {
                    get_cap_name(tmp, cap);
                    rsbac_printk(KERN_INFO
                         "capable(): pid %u(%s), uid %u: add missing user max_cap %s to transaction %u!\n",
                         current->pid, current->comm,
                         __kuid_val(current_uid()),
                         tmp,
                         cap_learn_ta);
                    rsbac_kfree(tmp);
                  }
                i_attr_val1.max_caps_user |= i_cap_vector;
                if (rsbac_ta_set_attr(cap_learn_ta,
		                      SW_CAP,
                                      T_PROCESS,
                                      i_tid,
				      A_max_caps_user,
				      i_attr_val1))
                  {
                    rsbac_pr_set_error (A_max_caps_user);
                  }
                i_tid.user = __kuid_val(current_uid());
                if (rsbac_ta_get_attr(cap_learn_ta,
                                      SW_CAP,
                                      T_USER,
                                      i_tid,
                                      A_max_caps,
                                      &i_attr_val1,
                                      FALSE))
                  {
                    rsbac_pr_get_error(A_max_caps);
                  }
                else
                  {
                    struct cred *override_cred;

                    i_attr_val1.max_caps |= i_cap_vector;
 		    if (rsbac_ta_set_attr(cap_learn_ta,
 		                          SW_CAP,
                                          T_USER,
                                          i_tid,
                                          A_max_caps,
                                          i_attr_val1))
                      {
                        rsbac_pr_set_error (A_max_caps);
                      }
                    /* set effective cap for process */
                    override_cred = prepare_creds();
                    if (override_cred)
                      {
                        cap_raise(override_cred->cap_permitted, cap);
                        cap_raise(override_cred->cap_effective, cap);
                        cap_raise(override_cred->cap_inheritable, cap);
                        commit_creds(override_cred);
                        res = true;
                      }
                  }
              }
            else
#endif
              if(rsbac_cap_log_missing)
                {
                  tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                  if(tmp)
                    {
                      get_cap_name(tmp, cap);
                      rsbac_printk(KERN_DEBUG
                         "capable(): pid %u(%s), uid %u: missing user max_cap %s!\n",
                         current->pid, current->comm,
                         __kuid_val(current_uid()),
                         tmp);
                      rsbac_kfree(tmp);
                    }
                }
          }
      }


    if (rsbac_ta_get_attr(cap_learn_ta,
                       SW_CAP,
                       T_PROCESS,
                       i_tid,
                       A_max_caps_program,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_pr_get_error(A_max_caps_program);
      }
    else
      {
        if(!(i_attr_val1.max_caps_program & i_cap_vector))
          {
#if defined(CONFIG_RSBAC_CAP_LEARN)
            if (rsbac_cap_learn)
              {
                struct file *file_p;

                i_attr_val1.max_caps_program |= i_cap_vector;
                if (rsbac_ta_set_attr(cap_learn_ta,
		                      SW_CAP,
                                      T_PROCESS,
				      i_tid,
				      A_max_caps_program,
				      i_attr_val1)) {
		  rsbac_pr_set_error (A_max_caps_program);
                }
                file_p = get_task_exe_file(current);
                if (file_p) {
                  if (file_p->f_path.dentry && file_p->f_path.dentry->d_inode) {
                    i_tid.file.device = file_p->f_path.dentry->d_sb->s_dev;
                    i_tid.file.inode = file_p->f_path.dentry->d_inode->i_ino;
                    i_tid.file.dentry_p = file_p->f_path.dentry;
                    tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                    if(tmp)
                      {
                        char * target_id_name;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
                        target_id_name = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
#else
                        target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
#endif
                        if(target_id_name)
                          {
                            get_cap_name(tmp, cap);
                            rsbac_printk(KERN_INFO
                                     "capable(): pid %u(%s), uid %u: add missing program max_cap %s to FILE %s to transaction %u!\n",
                                     current->pid, current->comm,
                                     __kuid_val(current_uid()),
                                     tmp,
                                     get_target_name(NULL, T_FILE, target_id_name, i_tid),
                                     cap_learn_ta);
                            rsbac_kfree(target_id_name);
                          }
                        rsbac_kfree(tmp);
                      }
                    if (rsbac_ta_get_attr(cap_learn_ta,
                                          SW_CAP,
                                          T_FILE,
                                          i_tid,
                                          A_max_caps,
                                          &i_attr_val1,
                                          FALSE))
                      {
                        rsbac_pr_get_error(A_max_caps);
                      }
                    else
                      {
                        struct cred *override_cred;

                        i_attr_val1.max_caps |= i_cap_vector;
 		        if (rsbac_ta_set_attr(cap_learn_ta,
 		                        SW_CAP,
					T_FILE,
					i_tid,
					A_max_caps,
					i_attr_val1))
                          {
                            rsbac_pr_set_error (A_max_caps);
                          }
                        /* set effective cap for process */
                        override_cred = prepare_creds();
                        if (override_cred)
                          {
                            cap_raise(override_cred->cap_permitted, cap);
                            cap_raise(override_cred->cap_effective, cap);
                            cap_raise(override_cred->cap_inheritable, cap);
			    commit_creds(override_cred);
			    res = true;
                          }
                      }
                  }
                  fput(file_p);
                }
              }
            else
#endif
              if(rsbac_cap_log_missing)
                {
                  tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                  if(tmp)
                    {
                      get_cap_name(tmp, cap);
                      rsbac_printk(KERN_DEBUG
                         "capable(): pid %u(%s), uid %u: missing program max_cap %s!\n",
                         current->pid, current->comm,
                         __kuid_val(current_uid()),
                         tmp);
                      rsbac_kfree(tmp);
                    }
                }
          }
      }
    return res;
  }
#endif
