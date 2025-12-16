/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of RSBAC general system calls      */
/* Author and (C) 1999-2024: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 13/Dec/2024                        */
/*************************************************** */

#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/mac.h>
#include <rsbac/auth.h>
#include <rsbac/acl.h>
#include <rsbac/reg.h>
#include <rsbac/error.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/network.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <rsbac/rkmem.h>
#include <rsbac/gen_lists.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/namei.h>
#include <linux/syscalls.h>

#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/adf_syshelpers.h>
#include <rsbac/rc.h>
#include <rsbac/um.h>
#include <rsbac/um_types.h>
#include <rsbac/syscalls.h>

#ifdef CONFIG_RSBAC_NET_OBJ
#include <rsbac/network.h>
#endif
#ifdef CONFIG_RSBAC_UDF
#include <rsbac/udf.h>
#endif

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

extern struct semaphore rsbac_write_sem;

#ifdef CONFIG_RSBAC_XSTATS
extern __u64 syscall_count[RSYS_none];
#endif

/************************************************* */
/*              Declarations                       */
/************************************************* */

/************************************************* */
/*              General functions                  */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac/error.h.                 */

static int sys_rsbac_stats(void)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_stats(): calling ADF\n");
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

    return rsbac_stats();
  }

long sys_sync(void);

static int sys_rsbac_check(int correct, int check_inode)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;
    int result;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_check(): calling ADF\n");
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

    rsbac_printk(KERN_INFO
           "sys_rsbac_check(): triggering RSBAC consistency check, correct = %u, check_inode = %u!\n",
           correct, check_inode);

    result=rsbac_check_lists(correct);

    /* call other checks */
#if defined(CONFIG_RSBAC_ACL)
    if(!result)
	    result=rsbac_check_acl(correct);
#endif
#if defined(CONFIG_RSBAC_REG)
    if(!result)
	    result=rsbac_check_reg(correct, check_inode);
#endif

    return result;
  }

static int sys_rsbac_write(void)
  {
#if defined(CONFIG_RSBAC_AUTO_WRITE)
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_write(): calling ADF\n");
      }
#endif
    rsbac_target_id.scd = ST_rsbac;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_WRITE,
                           task_pid(current),
                           T_SCD,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    return rsbac_trigger_write(TRUE);
#else
    return 0;
#endif /* CONFIG_RSBAC_AUTO_WRITE */
  };

/************************************************* */
/*               Attribute functions               */
/************************************************* */

static int sys_rsbac_get_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t __user * tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t __user * value,
  int inherit)
    { 
      union rsbac_target_id_t k_tid;
      union rsbac_attribute_value_t k_value;
      int   err = 0;
      rsbac_boolean_t i_inherit;

      if(module > SW_NONE)
        return -RSBAC_EINVALIDMODULE;
      if(!tid || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!value)
        return -RSBAC_EINVALIDPOINTER;
      if(attr >= A_none)
        return -RSBAC_EINVALIDATTR;

      if(module == SW_NONE)
        {
          module = get_attr_module(attr);
          if(module == SW_NONE)
            return -RSBAC_EINVALIDMODULE;
        }

      /* get values from user space */
      rsbac_get_user(&k_tid, tid, sizeof(k_tid) );
      k_value.dummy = 0;

       switch (target) {
               case T_FD:
                       return -RSBAC_EINVALIDTARGET;
               case T_FILE:
               case T_DIR:
               case T_FIFO:
               case T_SYMLINK:
               case T_UNIXSOCK:
                       k_tid.file.dentry_p = NULL;
                       k_tid.dir.dentry_p = NULL;
                       break;
               case T_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                       if (RSBAC_UID_SET(k_tid.user) == RSBAC_UM_VIRTUAL_KEEP)
                         k_tid.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_tid.user));
                       else
                         if (   (RSBAC_UID_SET(k_tid.user) > RSBAC_UM_VIRTUAL_MAX)
                             && (RSBAC_UID_SET(k_tid.user) != RSBAC_UM_VIRTUAL_ALL)
                            )
                           return -RSBAC_EINVALIDTARGET;
#else
                       k_tid.user = RSBAC_UID_NUM(k_tid.user);
#endif
                       break;
               case T_GROUP:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                       if (RSBAC_GID_SET(k_tid.group) == RSBAC_UM_VIRTUAL_KEEP)
                         k_tid.group = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(k_tid.group));
                       else
                         if (   (RSBAC_GID_SET(k_tid.group) > RSBAC_UM_VIRTUAL_MAX)
                             && (RSBAC_GID_SET(k_tid.group) != RSBAC_UM_VIRTUAL_ALL)
                            )
                           return -RSBAC_EINVALIDTARGET;
#else
                       k_tid.group = RSBAC_GID_NUM(k_tid.group);
#endif
                       break;
               case T_PROCESS:
                       k_tid.process = find_pid_ns(k_tid.uprocess, &init_pid_ns);
                       if(!k_tid.process)
                         return -RSBAC_EINVALIDTARGET;
                       break;
               default:
                       break;
       }

      if(inherit)
        i_inherit = TRUE;
      else
        i_inherit = FALSE;

#ifdef CONFIG_RSBAC_NET_OBJ
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && (   !k_tid.netobj.sock_p
             || k_tid.netobj.remote_addr
             || !k_tid.netobj.sock_p->file
             || !k_tid.netobj.sock_p->file->f_path.dentry
             || !k_tid.netobj.sock_p->file->f_path.dentry->d_inode
             || (SOCKET_I(k_tid.netobj.sock_p->file->f_path.dentry->d_inode) != k_tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr(): calling ADF\n");
        }
#endif
      if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                             task_pid(current),
                             target,
                             k_tid,
                             attr,
                             k_value))
        {
          return -EPERM;
        }

      err = rsbac_ta_get_attr(ta_number, module, target, k_tid, attr, &k_value, i_inherit);
      /* put result value to user space */
      if(!err)
        {
          err = rsbac_put_user(&k_value, value, sizeof(k_value) );
        }
      return err;
    }      /* end of sys_rsbac_get_attr() */


static int sys_rsbac_get_attr_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  char __user * t_name,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t __user * value,
  int inherit)
    { 
      union rsbac_attribute_value_t k_value;
      struct dentry * t_dentry;
      int     err = 0;
      union rsbac_target_id_t tid;
/*    struct passwd * user_description_p; */
      rsbac_boolean_t i_inherit;
      struct path path;

      if(module > SW_NONE)
        return -RSBAC_EINVALIDMODULE;
      if(!t_name || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!value)
        return -RSBAC_EINVALIDPOINTER;
      if(attr >= A_none)
        return -RSBAC_EINVALIDATTR;

      if(module == SW_NONE)
        {
          module = get_attr_module(attr);
          if(module == SW_NONE)
            return -RSBAC_EINVALIDMODULE;
        }

      if(inherit)
        i_inherit = TRUE;
      else
        i_inherit = FALSE;

      /* get values from user space */
      rsbac_get_user(&k_value, value, sizeof(k_value) );
      switch (target) {
               case T_FD:
               case T_FILE:
               case T_DIR:
               case T_FIFO:
               case T_SYMLINK:
               case T_UNIXSOCK:
                       tid.file.dentry_p = NULL;
                       tid.dir.dentry_p = NULL;
                       break;
               default:
                       return -RSBAC_EINVALIDTARGET;
       }

      /* lookup filename */
      if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): call to user_path_at() returned %i\n", err);
            }
#endif
          goto out;
        }
      t_dentry = path.dentry;
      if (!t_dentry->d_inode)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): file not found\n");
            }
#endif
          err = -RSBAC_EINVALIDTARGET;
          goto out_dput;
        }

      switch (target)
        {
          /* is inode of right type? */
          case T_FD:
            if(S_ISREG(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISDIR(t_dentry->d_inode->i_mode))
              {
                target = T_DIR;
              }
            else
            if(S_ISLNK(t_dentry->d_inode->i_mode))
              {
                target = T_SYMLINK;
              }
            else
            if(S_ISFIFO(t_dentry->d_inode->i_mode))
              {
                target = T_FIFO;
              }
            else
            if(S_ISBLK(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISCHR(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISSOCK(t_dentry->d_inode->i_mode))
              {
                target = T_UNIXSOCK;
              }
            else
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no filesystem object\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FILE:
            if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                && !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no file\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DIR:
            if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no dir\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FIFO:
            /* is inode of type fifo? */
            if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no fifo\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_UNIXSOCK:
            /* is inode of type socket? */
            if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no socket\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_SYMLINK:
            if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no symlink\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DEV:
            if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): no dev\n");
                  }
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          default:
            err = -RSBAC_EINVALIDTARGET;
            goto out_dput;
        }

      if(target == T_DEV)
        {
          if(S_ISBLK(t_dentry->d_inode->i_mode))
            tid.dev.type = D_block;
          else
            tid.dev.type = D_char;
          tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
          tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
        }
      else
        {
          /* fill target id and call internal function */
          tid.file.device = t_dentry->d_sb->s_dev;
          tid.file.inode  = t_dentry->d_inode->i_ino;
          tid.file.dentry_p = t_dentry;
        }
      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr_n(): calling ADF\n");
        }
#endif
      if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                             task_pid(current),
                             target,
                             tid,
                             attr,
                             k_value))
        {
          err = -EPERM;
        }
      else
        {
          err = rsbac_ta_get_attr(ta_number, module, target, tid, attr, &k_value, i_inherit);
          /* put result value to user space */
          if(!err)
            rsbac_put_user(&k_value, value, sizeof(k_value) );
        }

out_dput:
      path_put(&path);

out:
      return err;
    }      /* end of sys_rsbac_get_attr_n() */

/************************************************************************** */

static int sys_rsbac_set_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t __user * tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t __user * value)
    { 
      union rsbac_target_id_t k_tid;
      union rsbac_attribute_value_t k_value;
      int   err = 0;
      
      if(module > SW_NONE)
        return -RSBAC_EINVALIDMODULE;
      if(!tid || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!value)
        return -RSBAC_EINVALIDPOINTER;
      if(attr >= A_none)
        return -RSBAC_EINVALIDATTR;

      if(module == SW_NONE)
        {
          module = get_attr_module(attr);
          if(module == SW_NONE)
            return -RSBAC_EINVALIDMODULE;
        }
#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_set_attr(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif
        
      /* get values from user space */
      rsbac_get_user(&k_tid, tid, sizeof(k_tid) );
      rsbac_get_user(&k_value, value, sizeof(k_value) );


      switch(target)
        {
          case T_PROCESS:
            k_tid.process = find_pid_ns(k_tid.uprocess, &init_pid_ns);
            if(!k_tid.process)
              return -RSBAC_EINVALIDTARGET;
            break;

#ifdef CONFIG_RSBAC_NET_OBJ
            /* sanity check before using pointer */
          case T_NETOBJ:
            if(   !k_tid.netobj.sock_p
               || k_tid.netobj.remote_addr
               || !k_tid.netobj.sock_p->file
               || !k_tid.netobj.sock_p->file->f_path.dentry
               || !k_tid.netobj.sock_p->file->f_path.dentry->d_inode
               || (SOCKET_I(k_tid.netobj.sock_p->file->f_path.dentry->d_inode) != k_tid.netobj.sock_p)
              )
              return -RSBAC_EINVALIDTARGET;
#endif
            break;
          case T_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(k_tid.user) == RSBAC_UM_VIRTUAL_KEEP)
              k_tid.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_tid.user));
            else
              if (   (RSBAC_UID_SET(k_tid.user) > RSBAC_UM_VIRTUAL_MAX)
                  && (RSBAC_UID_SET(k_tid.user) != RSBAC_UM_VIRTUAL_ALL)
                 )
                return -RSBAC_EINVALIDTARGET;
#else
            k_tid.user = RSBAC_UID_NUM(k_tid.user);
#endif
            break;
          case T_GROUP:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_GID_SET(k_tid.group) == RSBAC_UM_VIRTUAL_KEEP)
              k_tid.group = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(k_tid.group));
            else
              if (   (RSBAC_GID_SET(k_tid.group) > RSBAC_UM_VIRTUAL_MAX)
                  && (RSBAC_GID_SET(k_tid.group) != RSBAC_UM_VIRTUAL_ALL)
                 )
                return -RSBAC_EINVALIDTARGET;
#else
            k_tid.group = RSBAC_GID_NUM(k_tid.group);
#endif
            break;

          case T_FD:
          case T_FILE:
          case T_DIR:
          case T_FIFO:
          case T_SYMLINK:
          case T_UNIXSOCK:
            return -RSBAC_EINVALIDTARGET;

          default:
            break;
        }
      
      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        rsbac_printk(KERN_DEBUG
               "sys_rsbac_set_attr(): calling ADF\n");
#endif
      if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                             task_pid(current),
                             target,
                             k_tid,
                             attr,
                             k_value))
        {
          return -EPERM;
        }
      err = rsbac_ta_set_attr_ttl(ta_number, module, target, k_tid, attr, k_value, attr == A_udf_checked ? 0 : RSBAC_LIST_TTL_KEEP);
      return err;
    }      /* end of sys_rsbac_set_attr() */

static int sys_rsbac_set_attr_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  char __user * t_name,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t __user * value)
    {
      struct dentry * t_dentry;
      int     err = 0;
      union rsbac_attribute_value_t k_value;
      union rsbac_target_id_t  tid;
      struct path path;

      if(module > SW_NONE)
        return -RSBAC_EINVALIDMODULE;
      if(!t_name || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!value)
        return -RSBAC_EINVALIDPOINTER;
      if(attr >= A_none)
        return -RSBAC_EINVALIDATTR;
        
      if(module == SW_NONE)
        {
          module = get_attr_module(attr);
          if(module == SW_NONE)
            return -RSBAC_EINVALIDMODULE;
        }

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_set_attr_n(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif
      /* get values from user space */
      rsbac_get_user(&k_value, value, sizeof(k_value) );

      /* lookup filename */
      if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): call to user_path_at() returned %i\n", err);
#endif
          goto out;
        }
      t_dentry = path.dentry;
      if (!t_dentry->d_inode)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): file not found\n");
#endif
          err = -RSBAC_EINVALIDTARGET;
          goto out_dput;
        }

      switch (target)
        {
          /* is inode of right type? */
          case T_FD:
            if(S_ISREG(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISDIR(t_dentry->d_inode->i_mode))
              {
                target = T_DIR;
              }
            else
            if(S_ISLNK(t_dentry->d_inode->i_mode))
              {
                target = T_SYMLINK;
              }
            else
            if(S_ISFIFO(t_dentry->d_inode->i_mode))
              {
                target = T_FIFO;
              }
            else
            if(S_ISSOCK(t_dentry->d_inode->i_mode))
              {
                target = T_UNIXSOCK;
              }
            else
            if(S_ISBLK(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISCHR(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no filesystem object\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FILE:
            if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                && !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no file\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DIR:
            if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr(): no dir\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FIFO:
            /* is inode of type fifo? */
            if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no fifo\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_UNIXSOCK:
            /* is inode of type fifo? */
            if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no socket\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_SYMLINK:
            if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no symlink\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DEV:
            if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): no dev\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          default:
            err = -RSBAC_EINVALIDTARGET;
            goto out_dput;
        }

      if(target == T_DEV)
        {
          if(S_ISBLK(t_dentry->d_inode->i_mode))
            tid.dev.type = D_block;
          else
            tid.dev.type = D_char;
          tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
          tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
        }
      else
        {
          /* fill target id and call internal function */
          tid.file.device = t_dentry->d_sb->s_dev;
          tid.file.inode  = t_dentry->d_inode->i_ino;
          tid.file.dentry_p = t_dentry;
        }
      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_set_attr_n(): calling ADF\n");
#endif
      if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                             task_pid(current),
                             target,
                             tid,
                             attr,
                             k_value))
        {
          err = -EPERM;
        }
      else
        {
          err = rsbac_ta_set_attr_ttl(ta_number, module, target, tid, attr, k_value, attr == A_udf_checked ? 0 : RSBAC_LIST_TTL_KEEP);
        }

out_dput:
      path_put(&path);

out:
      return err;
    }      /* end of sys_rsbac_set_attr_n() */

/************************************************************************** */

static int sys_rsbac_remove_target(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  union rsbac_target_id_t __user * tid)
    { 
      union rsbac_target_id_t k_tid;
      int   err = 0;

      /* for adf_request */
      union rsbac_attribute_value_t rsbac_attribute_value;
      
      if(!tid || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
        
#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_remove_target(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

      /* get values from user space */
      rsbac_get_user(&k_tid, tid, sizeof(k_tid) );

      switch (target) {
        case T_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(k_tid.user) == RSBAC_UM_VIRTUAL_KEEP)
            k_tid.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_tid.user));
#else
          k_tid.user = RSBAC_UID_NUM(k_tid.user);
#endif
          break;
        case T_GROUP:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_GID_SET(k_tid.group) == RSBAC_UM_VIRTUAL_KEEP)
            k_tid.group = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(k_tid.group));
#else
          k_tid.group = RSBAC_GID_NUM(k_tid.group);
#endif
          break;
        case T_PROCESS:
          k_tid.process = find_pid_ns(k_tid.uprocess, &init_pid_ns);
          if(!k_tid.process)
            return -RSBAC_EINVALIDTARGET;
          break;

        default:
          break;
      }

      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target(): calling ADF\n");
#endif
      rsbac_attribute_value.dummy = 0;
      if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                             task_pid(current),
                             target,
                             k_tid,
                             A_none,
                             rsbac_attribute_value))
        {
          return -EPERM;
        }
      err = rsbac_ta_remove_target(ta_number, target, &k_tid);
      return err;
    }      /* end of sys_rsbac_remove_target() */

static int sys_rsbac_remove_target_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  char __user * t_name)
    { 
      struct dentry * t_dentry;
      int     err = 0;
      union rsbac_target_id_t  tid;

      /* for adf_request */
      union rsbac_attribute_value_t rsbac_attribute_value;

/*    struct passwd * user_description_p; */
      
      struct path path;

      if(!t_name || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_remove_target_n(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

      /* lookup filename */
      if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): call to user_path_at() returned %i\n", err);
#endif
          goto out;
        }
      t_dentry = path.dentry;
      if (!t_dentry->d_inode)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): file not found\n");
#endif
          err = -RSBAC_EINVALIDTARGET;
          goto out_dput;
        }

      switch (target)
        {
          /* is inode of right type? */
          case T_FD:
            if(S_ISREG(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISDIR(t_dentry->d_inode->i_mode))
              {
                target = T_DIR;
              }
            else
            if(S_ISLNK(t_dentry->d_inode->i_mode))
              {
                target = T_SYMLINK;
              }
            else
            if(S_ISFIFO(t_dentry->d_inode->i_mode))
              {
                target = T_FIFO;
              }
            else
            if(S_ISSOCK(t_dentry->d_inode->i_mode))
              {
                target = T_UNIXSOCK;
              }
            else
            if(S_ISBLK(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISCHR(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no filesystem object\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FILE:
            if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                && !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no file\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DIR:
            if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_get_attr(): no dir\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FIFO:
            /* is inode of type fifo? */
            if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no fifo\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_UNIXSOCK:
            /* is inode of type fifo? */
            if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no socket\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_SYMLINK:
            if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no symlink\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DEV:
            if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): no dev\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          default:
            err = -RSBAC_EINVALIDTARGET;
            goto out_dput;
        }

      if(target == T_DEV)
        {
          if(S_ISBLK(t_dentry->d_inode->i_mode))
            tid.dev.type = D_block;
          else
            tid.dev.type = D_char;
          tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
          tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
        }
      else
        {
          /* fill target id and call internal function */
          tid.file.device = t_dentry->d_sb->s_dev;
          tid.file.inode  = t_dentry->d_inode->i_ino;
          tid.file.dentry_p = t_dentry;
        }
      /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_remove_target_n(): calling ADF\n");
#endif
      rsbac_attribute_value.dummy = 0;
      if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                             task_pid(current),
                             target,
                             tid,
                             A_none,
                             rsbac_attribute_value))
        {
          err = -EPERM;
        }
      else
        {
          err = rsbac_ta_remove_target(ta_number, target, &tid);
        }

out_dput:
      path_put(&path);

out:
      return err;
    }      /* end of sys_rsbac_remove_target_n() */

static int sys_rsbac_list_all_dev(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_dev_desc_t __user * id_p,
  u_long maxnum)
  {
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        struct rsbac_dev_desc_t * k_id_p = NULL;

        count = rsbac_ta_list_all_dev(ta_number, &k_id_p);
        if(count <= 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );

        rsbac_kfree(k_id_p);

        if(unlikely(err < 0))
          return err;
        else
          return count;
      }
    else
      return rsbac_ta_list_all_dev(ta_number, NULL);
  }

static int sys_rsbac_list_all_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t __user * id_p,
  u_long maxnum)
  {
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        rsbac_uid_t * k_id_p = NULL;

        count = rsbac_ta_list_all_user(ta_number, &k_id_p);
        if(count <= 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );

        rsbac_kfree(k_id_p);

        if(unlikely(err < 0))
          return err;
        else
          return count;
      }
    else
      return rsbac_ta_list_all_user(ta_number, NULL);
  }

static int sys_rsbac_list_all_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t __user * id_p,
  u_long maxnum)
  {
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        rsbac_gid_t * k_id_p = NULL;

        count = rsbac_ta_list_all_group(ta_number, &k_id_p);
        if(count <= 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );

        rsbac_kfree(k_id_p);

        if(unlikely(err < 0))
          return err;
        else
          return count;
      }
    else
      return rsbac_ta_list_all_group(ta_number, NULL);
  }

static int sys_rsbac_list_all_ipc(rsbac_list_ta_number_t ta_number,
			   struct rsbac_ipc_t __user * id_p, u_long maxnum)
{
	int err = 0;
	long count;

	if (id_p && maxnum) {
		struct rsbac_ipc_t *k_id_p = NULL;

		count = rsbac_ta_list_all_ipc(ta_number, &k_id_p);
		if (count <= 0)
			return count;
		if (count > maxnum)
			count = maxnum;

		err = rsbac_put_user(k_id_p, id_p,
				   count * sizeof(*k_id_p));

		rsbac_kfree(k_id_p);

		if(unlikely(err < 0))
			return err;
		else
			return count;
	} else
		return rsbac_ta_list_all_ipc(ta_number, NULL);
}

static int sys_rsbac_net_list_all_netdev(
  rsbac_list_ta_number_t ta_number,
  rsbac_netdev_id_t __user * id_p,
  u_long maxnum)
  {
#ifdef CONFIG_RSBAC_NET_DEV
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        rsbac_netdev_id_t * k_id_p = NULL;

        count = rsbac_ta_net_list_all_netdev(ta_number, &k_id_p);
        if(count <= 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );

        rsbac_kfree(k_id_p);

        if(unlikely(err < 0))
          return err;
        else
          return count;
      }
    else
      return rsbac_ta_net_list_all_netdev(ta_number, NULL);

#else
    return -RSBAC_EINVALIDREQUEST;
#endif /* CONFIG_RSBAC_NET_DEV */
  }

static int sys_rsbac_net_template(rsbac_list_ta_number_t ta_number,
			   enum rsbac_net_temp_syscall_t call,
			   rsbac_net_temp_id_t id,
			   union rsbac_net_temp_syscall_data_t __user * data_p)
{
#ifdef CONFIG_RSBAC_NET_OBJ
	union rsbac_net_temp_syscall_data_t k_data;
	int err = 0;
	/* for adf_request */
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val;

	if (!id)
		return -RSBAC_EINVALIDVALUE;
	if (!data_p)
		return -RSBAC_EINVALIDPOINTER;

	/* get data values from user space */
	switch (call) {
	case NTS_set_address:
	case NTS_set_address_family:
	case NTS_set_type:
	case NTS_set_protocol:
	case NTS_set_netdev:
	case NTS_set_ports:
	case NTS_set_name:
	case NTS_new_template:
	case NTS_copy_template:
	case NTS_delete_template:
#ifdef CONFIG_RSBAC_FREEZE
		if (rsbac_freeze) {
			rsbac_printk(KERN_WARNING "sys_rsbac_net_template(): RSBAC configuration frozen, no administration allowed\n");
			return -EPERM;
		}
#endif
		if (call != NTS_delete_template) {
			err =
			    rsbac_get_user(&k_data, data_p, sizeof(k_data));
			if(unlikely(err < 0))
				return err;
		}
		break;
	case NTS_check_id:
	case NTS_get_address:
	case NTS_get_address_family:
	case NTS_get_type:
	case NTS_get_protocol:
	case NTS_get_netdev:
	case NTS_get_ports:
	case NTS_get_name:
		break;

	default:
		return -RSBAC_EINVALIDREQUEST;
	}

	if (   (call != NTS_new_template)
	    && (call != NTS_copy_template)
	    && !rsbac_ta_net_template_exists(ta_number, id)
           )
		return -RSBAC_EINVALIDTARGET;

	rsbac_pr_debug(aef, "calling ADF\n");
	i_tid.nettemp = id;
	i_attr_val.dummy = 0;
	switch (call) {
	case NTS_new_template:
		if (!rsbac_adf_request(R_CREATE,
				       task_pid(current),
				       T_NETTEMP,
				       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
				return -EPERM;
		break;

	case NTS_copy_template:
		if (!rsbac_ta_net_template_exist(ta_number, id)) {
			if (!rsbac_adf_request(R_CREATE,
					       task_pid(current),
					       T_NETTEMP,
					       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
				if (!rsbac_softmode)
#endif
					return -EPERM;
		} else {
			if (!rsbac_adf_request(R_WRITE,
					       task_pid(current),
					       T_NETTEMP,
					       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
				if (!rsbac_softmode)
#endif
					return -EPERM;
		}
		i_tid.nettemp = k_data.id;
		if (!rsbac_adf_request(R_READ,
				       task_pid(current),
				       T_NETTEMP,
				       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
				return -EPERM;
		break;

	case NTS_delete_template:
		if (!rsbac_adf_request(R_DELETE,
				       task_pid(current),
				       T_NETTEMP,
				       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
				return -EPERM;
		break;

	case NTS_get_address:
	case NTS_get_address_family:
	case NTS_get_type:
	case NTS_get_protocol:
	case NTS_get_netdev:
	case NTS_get_ports:
		if (!rsbac_adf_request(R_READ,
				       task_pid(current),
				       T_NETTEMP,
				       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
				return -EPERM;
		break;

	case NTS_set_address:
	case NTS_set_address_family:
	case NTS_set_type:
	case NTS_set_protocol:
	case NTS_set_netdev:
	case NTS_set_ports:
	case NTS_set_name:
		if (!rsbac_adf_request(R_WRITE,
				       task_pid(current),
				       T_NETTEMP,
				       i_tid, A_none, i_attr_val))
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode)
#endif
				return -EPERM;
		break;

	default:
		break;
	}

	err = rsbac_ta_net_template(ta_number, call, id, &k_data);
	if (!err) {
		/* put data values to user space */
		switch (call) {
		case NTS_check_id:
		case NTS_get_address:
		case NTS_get_address_family:
		case NTS_get_type:
		case NTS_get_protocol:
		case NTS_get_netdev:
		case NTS_get_ports:
		case NTS_get_name:
			err = rsbac_put_user(&k_data,
					   data_p,
					   sizeof(k_data));
			break;
		default:
			break;
		}
	}
	return err;

#else
	return -RSBAC_EINVALIDREQUEST;
#endif				/* NET_OBJ */
}

static int sys_rsbac_net_list_all_template(
  rsbac_list_ta_number_t ta_number,
  rsbac_net_temp_id_t __user * id_p,
  u_long maxnum)
  {
#ifdef CONFIG_RSBAC_NET_OBJ
    int err = 0;
    int count;
    union rsbac_target_id_t i_tid;
    union rsbac_attribute_value_t i_attr_val;

    i_tid.nettemp = 0;
    i_attr_val.dummy = 0;
    if (!rsbac_adf_request(R_READ,
                           task_pid(current),
                           T_NETTEMP,
                           i_tid,
                           A_none,
                           i_attr_val))
      return -EPERM;
    if(id_p && maxnum)
      {
        rsbac_net_temp_id_t * k_id_p = NULL;

        count = rsbac_ta_net_list_all_template(ta_number, &k_id_p);
        if(count <= 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );

        rsbac_kfree(k_id_p);

        if(unlikely(err < 0))
          return err;
        else
          return count;
      }
    else
      return rsbac_ta_net_list_all_template(ta_number, NULL);

#else
    return -RSBAC_EINVALIDREQUEST;
#endif /* CONFIG_RSBAC_NET_OBJ */
  }


/************************************************* */
/*                 ADF functions                   */
/************************************************* */

static int sys_rsbac_switch(enum rsbac_switch_target_t module, int value)
  {
#if defined(CONFIG_RSBAC_SWITCH) || defined(CONFIG_RSBAC_SOFTMODE)
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;
    char                        * switch_name;
    rsbac_boolean_t               changed = FALSE;
  
    /* call ADF */
    if(module >= SW_NONE)
      return -RSBAC_EINVALIDTARGET;
    if (   (value < 0)
#ifdef CONFIG_RSBAC_SOFTMODE_IND
        || (value > 3)
#else
        || (value > 1)
#endif
       )
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_SOFTMODE
    if(   rsbac_softmode_prohibit
       && (   (   (value == 1)
               && (module == SW_SOFTMODE)
              )
#ifdef CONFIG_RSBAC_SOFTMODE_IND
           || (value == 3)
#endif
          )
      )
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_switch(): setting of softmode prohibited!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "sys_rsbac_switch(): calling ADF\n");
#endif
    rsbac_target_id.dummy = 0;
    rsbac_attribute_value.switch_target = module;
    if (!rsbac_adf_request(R_SWITCH_MODULE,
                           task_pid(current),
                           T_NONE,
                           rsbac_target_id,
                           A_switch_target,
                           rsbac_attribute_value))
      {
            return -EPERM;
      }

    switch(value)
      {
#ifdef CONFIG_RSBAC_SOFTMODE_IND
        case 2:
        case 3:
          if (rsbac_ind_softmode[module] != value - 2)
            changed = TRUE;
          rsbac_ind_softmode[module] = value - 2;
          break;
#endif

        default:
          switch (module)
            {
#ifdef CONFIG_RSBAC_SOFTMODE
              case SW_SOFTMODE:
                  if (rsbac_softmode != value)
                    changed = TRUE;
                  rsbac_softmode = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_FREEZE
              case SW_FREEZE:
                  if(rsbac_freeze)
                    {
                      rsbac_printk(KERN_WARNING
                                   "sys_rsbac_switch(): RSBAC configuration frozen, no administration allowed!\n");
                      return -EPERM;
                    }
                  if (rsbac_freeze != value)
                    changed = TRUE;
                  rsbac_freeze = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_MAC
              case SW_MAC:
#ifndef CONFIG_RSBAC_SWITCH_ON
                  if(value)
                    return -RSBAC_EINVALIDMODULE;
#endif
                  if (rsbac_switch_mac != value)
                    changed = TRUE;
                  rsbac_switch_mac = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_FF
              case SW_FF:
                  if (rsbac_switch_ff != value)
                    changed = TRUE;
                  rsbac_switch_ff = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_RC
              case SW_RC:
#ifndef CONFIG_RSBAC_SWITCH_ON
                  if(value)
                    return -RSBAC_EINVALIDMODULE;
#endif
                  if (rsbac_switch_rc != value)
                    changed = TRUE;
                  rsbac_switch_rc = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
              case SW_AUTH:
                  if (rsbac_switch_auth != value)
                    changed = TRUE;
                  rsbac_switch_auth = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_ACL
              case SW_ACL:
                  if (rsbac_switch_acl != value)
                    changed = TRUE;
                  rsbac_switch_acl = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_CAP
              case SW_CAP:
                  if (rsbac_switch_cap != value)
                    changed = TRUE;
                  rsbac_switch_cap = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_JAIL
              case SW_JAIL:
                  if (rsbac_switch_jail != value)
                    changed = TRUE;
                  rsbac_switch_jail = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_RES
              case SW_RES:
                  if (rsbac_switch_res != value)
                    changed = TRUE;
                  rsbac_switch_res = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_UDF
              case SW_UDF:
                  if (rsbac_switch_udf != value)
                    changed = TRUE;
                  rsbac_switch_udf = value;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_MPROTECT
              case SW_MPROTECT:
                  if (rsbac_switch_mprotect != value)
                    changed = TRUE;
                  rsbac_switch_mprotect = value;
                  break;
#endif
              default:
                return -RSBAC_EINVALIDMODULE;
            }
      }

    switch_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
    if(switch_name)
      {
        int show_value = value;

        get_switch_target_name(switch_name, module);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
        switch(value)
          {
            case 2:
            case 3:
              strcat(switch_name, " softmode");
              show_value -= 2;
              break;
            default:
              break;
          }
#endif
        if (changed)
          rsbac_printk(KERN_WARNING
               "sys_rsbac_switch(): user %u changed RSBAC module %s to %i!\n",
               __kuid_val(current_uid()), switch_name, show_value);
        rsbac_kfree(switch_name);
      }
    return 0;
#else
    return -RSBAC_EINVALIDREQUEST;
#endif /* SWITCH || SOFTMODE*/
  }

/**
 * sys_rsbac_get_switch - get the module status 
 * (is switchable ? is softmodable ?)
 *
 * @module:		the target module
 * @value_p:		0: module is enabled
 * 			1: module is softmodded
 * @switchable_p:	0: module can be turned on
 * 			1: module can be turned off
 * 			2: softmode can be turned on, but not off
 * 			3: softmode can be turned on or off
 *
 * Returns 0 on success
 */
static int sys_rsbac_get_switch(enum rsbac_switch_target_t module,
			int __user * value_p,
			int __user * switchable_p)
{
	int                           value = 1; // default if module exists and RSBAC_SWITCH is not compiled
	int                           switchable = 0;
	int                           allow_softmode = 0;
	int                           err = 0;
	union rsbac_target_id_t       rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if(module >= SW_NONE)
		return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_DEBUG
	if(rsbac_debug_aef)
		rsbac_printk(KERN_DEBUG "sys_rsbac_get_switch(): calling ADF\n");
#endif
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if(!rsbac_adf_request(R_GET_STATUS_DATA,
				task_pid(current),
				T_SCD,
				rsbac_target_id,
				A_none,
				rsbac_attribute_value))
	{
		return -EPERM;
	}
	switch(module)
	{
		case SW_GEN:
			allow_softmode = 0;
			switchable = 0;
			break;
#ifdef CONFIG_RSBAC_UM
		case SW_UM:
			allow_softmode = 0;
			switchable = 0;
			break;
#endif
#ifdef CONFIG_RSBAC_REG
		case SW_REG:
			allow_softmode = 1;
			switchable = 0;
			break;
#endif
#ifdef CONFIG_RSBAC_SOFTMODE
		case SW_SOFTMODE:
			allow_softmode = 0;
			value = rsbac_softmode;
			switchable = (rsbac_softmode_prohibit?2:3);
			break;
#endif
#ifdef CONFIG_RSBAC_FREEZE
		case SW_FREEZE:
			allow_softmode = 0;
			value = rsbac_freeze;
			switchable = 1;
			break;
#endif
#ifdef CONFIG_RSBAC_MAC
		case SW_MAC:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_MAC
			value = rsbac_switch_mac;
#ifdef CONFIG_RSBAC_SWITCH_ON
			switchable = 3;
#else
			switchable = 2;
#endif
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_FF
		case SW_FF:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_FF
			value = rsbac_switch_ff;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_RC
		case SW_RC:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_RC
			value = rsbac_switch_rc;
#ifdef CONFIG_RSBAC_SWITCH_ON
			switchable = 3;
#else
			switchable = 2;
#endif
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_AUTH
		case SW_AUTH:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_AUTH
			value = rsbac_switch_auth;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_ACL
		case SW_ACL:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_ACL
			value = rsbac_switch_acl;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_CAP
		case SW_CAP:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_CAP
			value = rsbac_switch_cap;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_JAIL
		case SW_JAIL:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_JAIL
			value = rsbac_switch_jail;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_RES
		case SW_RES:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_RES
			value = rsbac_switch_res;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_UDF
		case SW_UDF:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_UDF
			value = rsbac_switch_udf;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
#ifdef CONFIG_RSBAC_MPROTECT
		case SW_MPROTECT:
			allow_softmode = 1;
#ifdef CONFIG_RSBAC_SWITCH_MPROTECT
			value = rsbac_switch_mprotect;
			switchable = 3;
#else
			switchable = 0;
#endif
			break;
#endif
		default:
			return -RSBAC_EINVALIDMODULE;
	}

#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if(allow_softmode) {
		value |= rsbac_ind_softmode[module] << 1;
		switchable |= (rsbac_softmode_prohibit?2:3) << 2;
	}
#endif
	if(value_p)
		err = rsbac_put_user(&value, value_p, sizeof(int));
	if(!err && switchable_p)
		err = rsbac_put_user(&switchable, switchable_p, sizeof(int));
	return err;
}

/************** MAC ***************/

#ifdef CONFIG_RSBAC_MAC
static int sys_rsbac_mac_set_curr_level(rsbac_security_level_t level,
                                 rsbac_mac_category_vector_t __user * categories_p)
  {
    rsbac_mac_category_vector_t k_categories;
    int err;

    if(!categories_p)
      return -RSBAC_EINVALIDPOINTER;
    err = rsbac_get_user(&k_categories, categories_p, sizeof(k_categories));
    if(unlikely(err < 0))
      return err;
    return rsbac_mac_set_curr_level(level, k_categories);
  }

static int sys_rsbac_mac_get_curr_level(rsbac_security_level_t __user * level_p,
                                 rsbac_mac_category_vector_t __user * categories_p)
  {
    int err = 0;
    rsbac_security_level_t k_level;
    rsbac_mac_category_vector_t k_categories;

    err = rsbac_mac_get_curr_level(&k_level, &k_categories);
    if(unlikely(err < 0))
      return err;
    if(level_p)
      {
        err = rsbac_put_user(&k_level, level_p, sizeof(k_level));
        if(unlikely(err < 0))
          return err;
      }
    if(categories_p)
      {
        err = rsbac_put_user(&k_categories, categories_p, sizeof(k_categories));
      }
    return err;
  }

static int sys_rsbac_mac_get_max_level(rsbac_security_level_t __user * level_p,
                                rsbac_mac_category_vector_t __user * categories_p)
  {
    int err = 0;
    rsbac_security_level_t k_level;
    rsbac_mac_category_vector_t k_categories;

    err = rsbac_mac_get_max_level(&k_level, &k_categories);
    if(unlikely(err < 0))
      return err;
    if(level_p)
      {
        err = rsbac_put_user(&k_level, level_p, sizeof(k_level));
        if(unlikely(err < 0))
          return err;
      }
    if(categories_p)
      {
        err = rsbac_put_user(&k_categories, categories_p, sizeof(k_categories));
      }
    return err;
  }

static int sys_rsbac_mac_get_min_level(rsbac_security_level_t __user * level_p,
                                rsbac_mac_category_vector_t __user * categories_p)
  {
    int err = 0;
    rsbac_security_level_t k_level;
    rsbac_mac_category_vector_t k_categories;

    err = rsbac_mac_get_min_level(&k_level, &k_categories);
    if(unlikely(err < 0))
      return err;
    if(level_p)
      {
        err = rsbac_put_user(&k_level, level_p, sizeof(k_level));
        if(unlikely(err < 0))
          return err;
      }
    if(categories_p)
      {
        err = rsbac_put_user(&k_categories, categories_p, sizeof(k_categories));
      }
    return err;
  }

/* Provide means for adding and removing of capabilities */
static int sys_rsbac_mac_add_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t upid,
  rsbac_uid_t uid,
  rsbac_time_t ttl)
  {
    rsbac_pid_t pid;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_mac_add_p_tru(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
      uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
    else
      if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    uid = RSBAC_UID_NUM(uid);
#endif

    pid = find_pid_ns(upid, &init_pid_ns);
    if(!pid)
      return -RSBAC_EINVALIDTARGET;

    return rsbac_mac_add_p_tru(ta_number, pid, uid, ttl);
  }

static int sys_rsbac_mac_remove_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t upid,
  rsbac_uid_t uid)
  {
    rsbac_pid_t pid;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_mac_remove_p_tru(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
      uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
    else
      if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    uid = RSBAC_UID_NUM(uid);
#endif

    pid = find_pid_ns(upid, &init_pid_ns);
    if(!pid)
      return -RSBAC_EINVALIDTARGET;
    return rsbac_mac_remove_p_tru(ta_number, pid, uid);
  }

static int sys_rsbac_mac_add_f_tru(
  rsbac_list_ta_number_t ta_number,
  char __user * filename,
  rsbac_uid_t uid,
  rsbac_time_t ttl)
  {
    struct dentry * t_dentry;
    int     err = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;

    struct path path;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_mac_add_f_tru(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
      uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
    else
      if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    uid = RSBAC_UID_NUM(uid);
#endif

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_mac)
          rsbac_printk(KERN_DEBUG "sys_rsbac_mac_add_f_tru(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
      t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;

    err = rsbac_mac_add_f_tru(ta_number, tid.file, uid, ttl);

out_dput:
    path_put(&path);

out:
    return err;
  }

static int sys_rsbac_mac_remove_f_tru(
  rsbac_list_ta_number_t ta_number,
  char __user * filename,
  rsbac_uid_t uid)
  {
    struct dentry * t_dentry;
    int     err = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;

    struct path path;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_mac_remove_f_tru(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
      uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
    else
      if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    uid = RSBAC_UID_NUM(uid);
#endif

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_mac)
          rsbac_printk(KERN_DEBUG "sys_rsbac_mac_remove_f_tru(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
      t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file or dir? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;

    err = rsbac_mac_remove_f_tru(ta_number, tid.file, uid);

out_dput:
    path_put(&path);
out:
    return err;
  }

/* trulist must have space for maxnum rsbac_uid_t entries! */
static int sys_rsbac_mac_get_f_trulist(
  rsbac_list_ta_number_t ta_number,
  char __user * filename,
  rsbac_uid_t __user trulist[],
  rsbac_time_t __user ttllist[],
  u_int maxnum)
  {
    struct dentry * t_dentry;
    int     err = 0, tmperr = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;
    rsbac_uid_t * k_trulist;
    rsbac_time_t * k_ttllist;

    struct path path;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;
    if(!trulist)
      return -RSBAC_EINVALIDPOINTER;
    if(maxnum <= 0)
      return -RSBAC_EINVALIDVALUE;
    if(maxnum > RSBAC_MAC_MAX_MAXNUM)
      maxnum = RSBAC_MAC_MAX_MAXNUM;

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_mac)
          rsbac_printk(KERN_DEBUG "sys_rsbac_mac_get_f_trulist(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
      t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file or dir? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;

    err = rsbac_mac_get_f_trulist(ta_number, tid.file, &k_trulist, &k_ttllist);
    if(err>0)
      {
        if(err > maxnum)
          err = maxnum;
        tmperr = rsbac_put_user(k_trulist, trulist,
                                sizeof(rsbac_uid_t) * err);
        if(tmperr < 0)
          err = tmperr;
        else
          {
            if(ttllist)
              {
                tmperr = rsbac_put_user(k_ttllist, ttllist,
                                        sizeof(rsbac_time_t) * err);
                if(tmperr < 0)
                  err = tmperr;
              }
          }
        rsbac_kfree(k_trulist);
        rsbac_kfree(k_ttllist);
      }

out_dput:
    path_put(&path);
out:
    return err;
  }

static int sys_rsbac_mac_get_p_trulist(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t upid,
  rsbac_uid_t __user trulist[],
  rsbac_time_t __user ttllist[],
  u_int maxnum)
  {
    int     err = 0, tmperr = 0;
    union rsbac_target_id_t  tid;
    rsbac_uid_t * k_trulist;
    rsbac_time_t * k_ttllist;

    if(!upid)
      return -RSBAC_EINVALIDTARGET;
    if(!trulist)
      return -RSBAC_EINVALIDPOINTER;
    if(maxnum <= 0)
      return -RSBAC_EINVALIDVALUE;
    if(maxnum > RSBAC_MAC_MAX_MAXNUM)
      maxnum = RSBAC_MAC_MAX_MAXNUM;

    tid.process = find_pid_ns(upid, &init_pid_ns);
    if(!tid.process)
      return -RSBAC_EINVALIDTARGET;

    err = rsbac_mac_get_p_trulist(ta_number, tid.process, &k_trulist, &k_ttllist);
    if(err>0)
      {
        if(err > maxnum)
          err = maxnum;
        tmperr = rsbac_put_user(k_trulist, trulist,
                                sizeof(rsbac_uid_t) * err);
        if(tmperr < 0)
          err = tmperr;
        else
          {
            if(ttllist)
              {
                tmperr = rsbac_put_user(k_ttllist, ttllist,
                                        sizeof(rsbac_time_t) * err);
                if(tmperr < 0)
                  err = tmperr;
              }
          }
        rsbac_kfree(k_trulist);
        rsbac_kfree(k_ttllist);
      }

    return err;
  }
#endif

/************** RC ***************/

#ifdef CONFIG_RSBAC_RC
static int sys_rsbac_rc_copy_role(
  rsbac_list_ta_number_t ta_number,
  rsbac_rc_role_id_t from_role,
  rsbac_rc_role_id_t to_role)
  {
    if(   (from_role > RC_role_max_value)
       || (from_role > RC_role_max_value))
      return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_rc_copy_role(): from %i, to %i!\n",
             from_role, to_role);
#endif
#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_rc_copy_role(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    /* call rc function and return its result */
    return rsbac_rc_sys_copy_role(ta_number, from_role, to_role);
  }

static int sys_rsbac_rc_copy_type(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_target_t         target,
        rsbac_rc_type_id_t     from_type,
        rsbac_rc_type_id_t     to_type)
  {
    if(   (from_type > RC_type_max_value)
       || (from_type > RC_type_max_value))
      return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_rc_copy_type(): from %i, to %i!\n",
             from_type, to_type);
#endif
#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_rc_copy_type(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    /* call rc function and return its result */
    return rsbac_rc_sys_copy_type(ta_number, target, from_type, to_type);
  }

/* Getting values */
static int sys_rsbac_rc_get_item (
        rsbac_list_ta_number_t  ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t __user * tid_p,
  union rsbac_rc_target_id_t __user * subtid_p,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t __user * value_p,
        rsbac_time_t          __user * ttl_p)
  {
    union rsbac_rc_target_id_t  k_tid;
    union rsbac_rc_target_id_t  k_subtid;
    union rsbac_rc_item_value_t k_value;
          rsbac_time_t          k_ttl;
    int err = 0;

    if(   (target >= RT_NONE)
       || (item >= RI_none))
      return -RSBAC_EINVALIDVALUE;
    /* get values from user space */
    rsbac_get_user(&k_tid, tid_p, sizeof(k_tid) );
    rsbac_get_user(&k_subtid, subtid_p, sizeof(k_subtid) );
    rsbac_get_user(&k_value, value_p, sizeof(k_value) );
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_rc_get_item(): target %i, item %i!\n",
             target, item);
#endif
    /* call rc function and return its result */
    err = rsbac_rc_sys_get_item(ta_number, target, k_tid, k_subtid,
                                item, &k_value, &k_ttl);
    /* put result value to user space */
    if(!err)
      {
        err = rsbac_put_user(&k_value, value_p, sizeof(k_value) );
        if(!err && ttl_p)
          err = rsbac_put_user(&k_ttl, ttl_p, sizeof(k_ttl) );
      }
    return err;
  }

/* Setting values */
static int sys_rsbac_rc_set_item(
  rsbac_list_ta_number_t        ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t __user * tid_p,
  union rsbac_rc_target_id_t __user * subtid_p,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t __user * value_p,
        rsbac_time_t            ttl)
  {
    union rsbac_rc_target_id_t  k_tid;
    union rsbac_rc_target_id_t  k_subtid;
    union rsbac_rc_item_value_t k_value;

    if(   (target >= RT_NONE)
       || (item >= RI_none))
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_rc_set_item(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    /* get values from user space */
    rsbac_get_user(&k_tid, tid_p, sizeof(k_tid) );
    rsbac_get_user(&k_subtid, subtid_p, sizeof(k_subtid) );
    rsbac_get_user(&k_value, value_p, sizeof(k_value) );
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_rc_set_item(): target %i, item %i!\n",
             target, item);
#endif
    /* call rc function and return its result */
    return rsbac_rc_sys_set_item(ta_number, target, k_tid, k_subtid, item, k_value, ttl);
  }

static int sys_rsbac_rc_get_list(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t      target,
  union rsbac_rc_target_id_t __user * tid_p,
  enum  rsbac_rc_item_t        item,
        u_int                  maxnum,
        __u32                __user * array_p,
        rsbac_time_t         __user * ttl_array_p)
  {
    union rsbac_rc_target_id_t  k_tid;
    int err;

    rsbac_get_user(&k_tid, tid_p, sizeof(k_tid));
    if(array_p)
      {
        __u32 * k_array_p;
        rsbac_time_t * k_ttl_array_p;

        if(!maxnum)
          return -RSBAC_EINVALIDVALUE;
        /* call rc function and return its result */
        err = rsbac_rc_get_list(ta_number, target, k_tid, item,
                                &k_array_p, &k_ttl_array_p);
        /* put result value to user space */
        if(err > 0)
          {
            int tmperr;

            if(err > maxnum)
              err = maxnum;
            tmperr = rsbac_put_user(k_array_p, array_p, err * sizeof(*k_array_p) );
            if(tmperr)
              err = tmperr;
            rsbac_kfree(k_array_p);
            if(k_ttl_array_p && ttl_array_p)
              {
                tmperr = rsbac_put_user(k_ttl_array_p, ttl_array_p, err * sizeof(*k_ttl_array_p) );
                if(tmperr)
                  err = tmperr;
              }
            rsbac_kfree(k_ttl_array_p);
          }
        return err;
      }
    else
      return rsbac_rc_get_list(ta_number, target, k_tid, item, NULL, NULL);
  }

/* Set own role */
static int sys_rsbac_rc_change_role (rsbac_rc_role_id_t role, char __user * pass)
  {
    if(role > RC_role_max_value)
      return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_rc)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_rc_change_role(): role %i!\n",
             role);
#endif
    /* call rc function and return its result */
    return rsbac_rc_sys_change_role(role, pass);
  }

/* Getting own effective rights */
static int sys_rsbac_rc_get_eff_rights_n(
        rsbac_list_ta_number_t      ta_number,
  enum  rsbac_target_t              target,
        char                      __user * t_name,
        rsbac_rc_request_vector_t __user * request_vector_p,
        rsbac_time_t              __user * ttl_p)
  {
      struct dentry * t_dentry;
      int     err = 0;
      rsbac_rc_request_vector_t k_req_vec;
      rsbac_time_t          k_ttl;
      union rsbac_target_id_t  tid;

      struct path path;

      if(!t_name || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;

      if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_rc)
            rsbac_printk(KERN_DEBUG "sys_rsbac_rc_get_eff_rights_n(): call to user_path_at() returned %i\n", err);
#endif
          goto out;
        }
      t_dentry = path.dentry;
      if (!t_dentry->d_inode)
        {
          err = -RSBAC_EINVALIDTARGET;
          goto out_dput;
        }
        
      switch (target)
        {
          case T_FD:
            if(S_ISREG(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISDIR(t_dentry->d_inode->i_mode))
              {
                target = T_DIR;
              }
            else
            if(S_ISLNK(t_dentry->d_inode->i_mode))
              {
                target = T_SYMLINK;
              }
            else
            if(S_ISFIFO(t_dentry->d_inode->i_mode))
              {
                target = T_FIFO;
              }
            else
            if(S_ISSOCK(t_dentry->d_inode->i_mode))
              {
                target = T_UNIXSOCK;
              }
            else
            if(S_ISBLK(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
            if(S_ISCHR(t_dentry->d_inode->i_mode))
              {
                target = T_FILE;
              }
            else
              {
#ifdef CONFIG_RSBAC_DEBUG
                if (rsbac_debug_aef)
                  rsbac_printk(KERN_DEBUG "sys_rsbac_rc_get_eff_rights_n(): no filesystem object\n");
#endif
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FILE:
            /* is inode of type file, symlink or block/char device? */
            if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                && !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              { /* This is no file or device */
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DIR:
            if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
              { /* This is no file */
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_FIFO:
            /* is inode of type fifo? */
            if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
              { /* This is no file or device */
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_UNIXSOCK:
            /* is inode of type fifo? */
            if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
              {
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_SYMLINK:
            /* is inode of type symlink? */
            if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
              { /* This is no file or device */
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          case T_DEV:
            /* is inode of type block/char device? */
            if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
              { /* This is no dev */
                err = -RSBAC_EINVALIDTARGET;
                goto out_dput;
              }
            break;

          default:
            err = -RSBAC_EINVALIDTARGET;
            goto out_dput;
        }

      if(target == T_DEV)
        {
          if(S_ISBLK(t_dentry->d_inode->i_mode))
            tid.dev.type = D_block;
          else
            tid.dev.type = D_char;
          tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
          tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
        }
      else
        {
          /* fill target id and call internal function */
          tid.file.device = t_dentry->d_sb->s_dev;
          tid.file.inode  = t_dentry->d_inode->i_ino;
          tid.file.dentry_p = t_dentry;
        }
      err = rsbac_rc_sys_get_eff_rights(ta_number, target, tid, &k_req_vec, &k_ttl);
      /* put result value to user space */
      if(!err)
        {
          err = rsbac_put_user(&k_req_vec, request_vector_p, sizeof(k_req_vec) );
          if(!err && ttl_p)
            err = rsbac_put_user(&k_ttl, ttl_p, sizeof(k_ttl) );
        }

  out_dput:
      path_put(&path);

  out:
      return err;
  }

/* Get current process role */
static int sys_rsbac_rc_get_current_role (rsbac_rc_role_id_t __user * role_p)
  {
    rsbac_rc_role_id_t k_role;
    int err;

    if(!role_p)
      return -RSBAC_EINVALIDPOINTER;
    /* call rc function and return its result */
    err = rsbac_rc_sys_get_current_role(&k_role);
    if(!err)
      {
        err = rsbac_put_user(&k_role, role_p, sizeof(k_role) );
      }
    return err;
  }

static int sys_rsbac_rc_select_fd_create_type(rsbac_rc_type_id_t type)
{
	int err;

	err = rsbac_rc_select_fd_create_type(type);

	return err;
}
#endif

/************** AUTH ***************/

#ifdef CONFIG_RSBAC_AUTH
/* Provide means for adding and removing of capabilities */
static int sys_rsbac_auth_add_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_upid_t upid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl)
  {
    union rsbac_target_id_t  caller_tid, tid;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(cap_range.first) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.first = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.first));
    else
      if (   (RSBAC_UID_SET(cap_range.first) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.first) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
    if (RSBAC_UID_SET(cap_range.last) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.last = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.last));
    else
      if (   (RSBAC_UID_SET(cap_range.last) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.last) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    cap_range.first = RSBAC_UID_NUM(cap_range.first);
    cap_range.last = RSBAC_UID_NUM(cap_range.last);
#endif

    if(cap_range.first > cap_range.last)
      return -RSBAC_EINVALIDVALUE;
    if(   (RSBAC_UID_NUM(cap_range.first) > RSBAC_AUTH_MAX_RANGE_UID)
       || (RSBAC_UID_NUM(cap_range.last) > RSBAC_AUTH_MAX_RANGE_UID)
      )
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_auth_add_p_cap(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    /* check auth_may_set_cap of calling process */
    caller_tid.process = task_pid(current);
    if (rsbac_get_attr(SW_AUTH,
                       T_PROCESS,
                       caller_tid,
                       A_auth_may_set_cap,
                       &rsbac_attribute_value,
                       FALSE))
      {
        rsbac_pr_get_error(A_auth_may_set_cap);
        return -EPERM;
      }

    tid.process = find_pid_ns(upid, &init_pid_ns);
    if(!tid.process)
      return -RSBAC_EINVALIDTARGET;

    /* if auth_may_set_cap is not set, then call ADF */
    if (!rsbac_attribute_value.auth_may_set_cap)
      {
        rsbac_pr_debug(adf_auth,
                       "adding AUTH cap %u:%u to process %u denied for process %u without auth_may_set_cap, calling ADF!\n",
                       cap_range.first,
                       cap_range.last,
                       pid_nr(tid.process),
                       pid_nr(caller_tid.process));
        rsbac_pr_debug(aef, "calling ADF\n");
        rsbac_attribute_value.auth_cap_range = cap_range;
        if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                               caller_tid.process,
                               T_PROCESS,
                               tid,
                               A_auth_add_p_cap,
                               rsbac_attribute_value))
          return -EPERM;
      }
    else
      {
        rsbac_pr_debug(adf_auth,
                       "adding AUTH cap %u:%u to process %u allowed for process %u!\n",
                       cap_range.first,
                       cap_range.last,
                       pid_nr(tid.process),
                       pid_nr(caller_tid.process));
      }
    return rsbac_auth_add_p_cap(ta_number, tid.process, cap_type, cap_range, ttl);
  }

static int sys_rsbac_auth_remove_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_upid_t upid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range)
  {
    union rsbac_target_id_t  caller_tid, tid;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(cap_range.first) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.first = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.first));
    else
      if (   (RSBAC_UID_SET(cap_range.first) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.first) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
    if (RSBAC_UID_SET(cap_range.last) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.last = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.last));
    else
      if (   (RSBAC_UID_SET(cap_range.last) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.last) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    cap_range.first = RSBAC_UID_NUM(cap_range.first);
    cap_range.last = RSBAC_UID_NUM(cap_range.last);
#endif
    if(cap_range.first > cap_range.last)
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_auth_remove_p_cap(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    /* check auth_may_set_cap of calling process */
    caller_tid.process = task_pid(current);
    if (rsbac_get_attr(SW_AUTH,
                       T_PROCESS,
                       caller_tid,
                       A_auth_may_set_cap,
                       &rsbac_attribute_value,
                       FALSE))
      {
        rsbac_pr_get_error(A_auth_may_set_cap);
        return -EPERM;
      }

    tid.process = find_pid_ns(upid, &init_pid_ns);
    if(!tid.process)
      return -RSBAC_EINVALIDTARGET;

    /* if auth_may_set_cap is not set, then call ADF */
    if (!rsbac_attribute_value.auth_may_set_cap)
      {
        rsbac_pr_debug(adf_auth,
                       "removing AUTH cap %u:%u from process %u denied for process %u without auth_may_set_cap, calling ADF!\n",
                       cap_range.first,
                       cap_range.last,
                       pid_nr(tid.process),
                       pid_nr(caller_tid.process));
        rsbac_pr_debug(aef, "calling ADF\n");
        rsbac_attribute_value.auth_cap_range = cap_range;
        if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                               caller_tid.process,
                               T_PROCESS,
                               tid,
                               A_auth_remove_p_cap,
                               rsbac_attribute_value))
          return -EPERM;
      }
    else
      {
        rsbac_pr_debug(adf_auth,
                       "removing AUTH cap %u:%u from process %u allowed for process %u!\n",
                       cap_range.first,
                       cap_range.last,
                       pid_nr(tid.process),
                       pid_nr(caller_tid.process));
      }
    return rsbac_auth_remove_p_cap(ta_number, tid.process, cap_type, cap_range);
  }

static int sys_rsbac_auth_add_f_cap(
         rsbac_list_ta_number_t   ta_number,
         char                  __user * filename,
  enum   rsbac_auth_cap_type_t    cap_type,
  struct rsbac_auth_cap_range_t   cap_range,
         rsbac_time_t             ttl)
  {
    struct dentry * t_dentry;
    int     err = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;
#if defined(CONFIG_RSBAC_AUTH)
    union rsbac_attribute_value_t rsbac_attribute_value;
#endif

    struct path path;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(cap_range.first) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.first = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.first));
    else
      if (   (RSBAC_UID_SET(cap_range.first) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.first) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
    if (RSBAC_UID_SET(cap_range.last) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.last = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.last));
    else
      if (   (RSBAC_UID_SET(cap_range.last) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.last) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    cap_range.first = RSBAC_UID_NUM(cap_range.first);
    cap_range.last = RSBAC_UID_NUM(cap_range.last);
#endif
    if(cap_range.first > cap_range.last)
      return -RSBAC_EINVALIDVALUE;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;
    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDTARGET;
    if(cap_range.first > cap_range.last)
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_auth_add_f_cap(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_auth)
          rsbac_printk(KERN_DEBUG "sys_rsbac_auth_add_f_cap(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
    t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;
#if defined(CONFIG_RSBAC_AUTH)
    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "sys_rsbac_auth_add_f_cap(): calling ADF\n");
#endif
    rsbac_attribute_value.auth_cap_range = cap_range;
    if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                           task_pid(current),
                           target,
                           tid,
                           A_auth_add_f_cap,
                           rsbac_attribute_value))
      {
        err = -EPERM;
      }
    else
#endif
      err = rsbac_auth_add_f_cap(ta_number, tid.file, cap_type, cap_range, ttl);

out_dput:
    path_put(&path);
out:
    return err;
  }

static int sys_rsbac_auth_remove_f_cap(
         rsbac_list_ta_number_t   ta_number,
         char                  __user * filename,
  enum   rsbac_auth_cap_type_t    cap_type,
  struct rsbac_auth_cap_range_t   cap_range)
  {
    struct dentry * t_dentry;
    int     err = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;

    /* for adf_request */
#if defined(CONFIG_RSBAC_AUTH)
    union rsbac_attribute_value_t rsbac_attribute_value;
#endif

    struct path path;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;
    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDTARGET;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(cap_range.first) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.first = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.first));
    else
      if (   (RSBAC_UID_SET(cap_range.first) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.first) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
    if (RSBAC_UID_SET(cap_range.last) == RSBAC_UM_VIRTUAL_KEEP)
      cap_range.last = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(cap_range.last));
    else
      if (   (RSBAC_UID_SET(cap_range.last) > RSBAC_UM_VIRTUAL_MAX)
          && (RSBAC_UID_SET(cap_range.last) != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    cap_range.first = RSBAC_UID_NUM(cap_range.first);
    cap_range.last = RSBAC_UID_NUM(cap_range.last);
#endif
    if(cap_range.first > cap_range.last)
      return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_FREEZE
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_auth_remove_f_cap(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_auth)
          rsbac_printk(KERN_DEBUG "sys_rsbac_auth_remove_f_cap(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
    t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file or dir? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;
#if defined(CONFIG_RSBAC_AUTH)
    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_auth_add_f_cap(): calling ADF\n");
#endif
    rsbac_attribute_value.auth_cap_range = cap_range;
    if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                           task_pid(current),
                           target,
                           tid,
                           A_auth_remove_f_cap,
                           rsbac_attribute_value))
      {
        err = -EPERM;
      }
    else
#endif
      err = rsbac_auth_remove_f_cap(ta_number, tid.file, cap_type, cap_range);

out_dput:
    path_put(&path);
out:
    return err;
  }

/* caplist must have space for maxnum auth_cap_range entries - first and last each! */
static int sys_rsbac_auth_get_f_caplist(
         rsbac_list_ta_number_t   ta_number,
         char                  __user * filename,
  enum   rsbac_auth_cap_type_t    cap_type,
  struct rsbac_auth_cap_range_t  __user caplist[],
         rsbac_time_t            __user ttllist[],
         u_int                    maxnum)
  {
    struct dentry * t_dentry;
    int     err = 0, tmperr = 0;
    enum  rsbac_target_t     target;
    union rsbac_target_id_t  tid;
    struct rsbac_auth_cap_range_t * k_caplist;
    rsbac_time_t * k_ttllist;

    /* for adf_request */
#if defined(CONFIG_RSBAC_AUTH)
    union rsbac_attribute_value_t rsbac_attribute_value;
#endif

    struct path path;

    if(!filename)
      return -RSBAC_EINVALIDTARGET;
    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDTARGET;
    if(!caplist)
      return -RSBAC_EINVALIDPOINTER;
    if(maxnum <= 0)
      return -RSBAC_EINVALIDVALUE;
    if(maxnum > RSBAC_AUTH_MAX_MAXNUM)
      maxnum = RSBAC_AUTH_MAX_MAXNUM;

    if ((err = user_path_at(AT_FDCWD, filename, 0, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_auth)
          rsbac_printk(KERN_DEBUG "sys_rsbac_auth_get_f_caplist(): call to user_path_at() returned %i\n", err);
#endif
        goto out;
      }
    t_dentry = path.dentry;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file or dir? */
    if(S_ISREG(t_dentry->d_inode->i_mode))
      target = T_FILE;
    else
    if(S_ISDIR(t_dentry->d_inode->i_mode))
      target = T_DIR;
    else
      { /* This is no file or dir */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    tid.file.device = t_dentry->d_sb->s_dev;
    tid.file.inode  = t_dentry->d_inode->i_ino;
    tid.file.dentry_p = t_dentry;
#if defined(CONFIG_RSBAC_AUTH)
    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_auth_get_f_caplist(): calling ADF\n");
#endif
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                           task_pid(current),
                           target,
                           tid,
                           A_auth_get_caplist,
                           rsbac_attribute_value))
      {
        err = -EPERM;
        goto out_dput;
      }
#endif
    err = rsbac_auth_get_f_caplist(ta_number, tid.file, cap_type, &k_caplist, &k_ttllist);
    if(err>0)
      {
        if(err > maxnum)
          err = maxnum;
        tmperr = rsbac_put_user(k_caplist, caplist,
                                sizeof(struct rsbac_auth_cap_range_t) * err);
        if(tmperr < 0)
          err = tmperr;
        else
          {
            if(ttllist)
              {
                tmperr = rsbac_put_user(k_ttllist, ttllist,
                                        sizeof(rsbac_time_t) * err);
                if(tmperr < 0)
                  err = tmperr;
              }
          }
        rsbac_kfree(k_caplist);
        rsbac_kfree(k_ttllist);
      }

out_dput:
    path_put(&path);
out:
    return err;
  }

static int sys_rsbac_auth_get_p_caplist(
         rsbac_list_ta_number_t ta_number,
         rsbac_upid_t           upid,
  enum   rsbac_auth_cap_type_t  cap_type,
  struct rsbac_auth_cap_range_t __user caplist[],
         rsbac_time_t           __user ttllist[],
         u_int                  maxnum)
  {
    int     err = 0, tmperr = 0;
    union rsbac_target_id_t  tid;
    struct rsbac_auth_cap_range_t * k_caplist;
    rsbac_time_t * k_ttllist;

    /* for adf_request */
#if defined(CONFIG_RSBAC_AUTH)
    union rsbac_attribute_value_t rsbac_attribute_value;
#endif

    if(!upid)
      return -RSBAC_EINVALIDTARGET;
    if(cap_type >= ACT_none)
      return -RSBAC_EINVALIDVALUE;
    if(!caplist)
      return -RSBAC_EINVALIDPOINTER;
    if(maxnum <= 0)
      return -RSBAC_EINVALIDVALUE;
    if(maxnum > RSBAC_AUTH_MAX_MAXNUM)
      maxnum = RSBAC_AUTH_MAX_MAXNUM;

    tid.process = find_pid_ns(upid, &init_pid_ns);
    if (!tid.process)
      return -RSBAC_EINVALIDTARGET;
#if defined(CONFIG_RSBAC_AUTH)
    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef) rsbac_printk(KERN_DEBUG "sys_rsbac_auth_get_p_caplist(): calling ADF\n");
#endif
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                           task_pid(current),
                           T_PROCESS,
                           tid,
                           A_auth_get_caplist,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }
#endif
    err = rsbac_auth_get_p_caplist(ta_number, tid.process, cap_type,
                                   &k_caplist, &k_ttllist);
    if(err>0)
      {
        if(err > maxnum)
          err = maxnum;
        tmperr = rsbac_put_user(k_caplist, caplist,
                                sizeof(struct rsbac_auth_cap_range_t) * err);
        if(tmperr < 0)
          err = tmperr;
        else
          {
            if(ttllist)
              {
                tmperr = rsbac_put_user(k_ttllist, ttllist,
                                        sizeof(rsbac_time_t) * err);
                if(tmperr < 0)
                  err = tmperr;
              }
          }
        rsbac_kfree(k_caplist);
        rsbac_kfree(k_ttllist);
      }

    return err;
  }
#endif

/************** RES ***************/

#ifdef CONFIG_RSBAC_RES
static int sys_rsbac_res_get_user_limit(rsbac_list_ta_number_t ta_number,
				rsbac_uid_t uid,
				enum rsbac_attribute_t attr,
				rsbac_res_desc_t res_num,
				rsbac_res_limit_t __user * value_p,
				rsbac_time_t __user * ttl_p,
				rsbac_boolean_t inherit)
{
  union rsbac_target_id_t k_tid;
  union rsbac_attribute_value_t k_attr_val;
  rsbac_res_limit_t k_value;
  rsbac_time_t k_ttl;
  int err;

  if (!value_p)
    return -RSBAC_EINVALIDPOINTER;
  switch (attr)
    {
      case A_res_min:
      case A_res_max:
        break;
      default:
        return -RSBAC_EINVALIDATTR;
    }

#ifdef CONFIG_RSBAC_UM_VIRTUAL
  if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
    uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
  else
    if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
      return -RSBAC_EINVALIDVALUE;
#else
  uid = RSBAC_UID_NUM(uid);
#endif

  k_tid.user = uid;
  k_attr_val.dummy = 0;

  /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "sys_rsbac_res_get_user_limit(): calling ADF\n");
    }
#endif
  if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                         task_pid(current),
                         T_USER,
                         k_tid,
                         attr,
                         k_attr_val))
    {
      return -EPERM;
    }

  err = rsbac_ta_get_res_limit(ta_number, T_USER, &k_tid, attr, res_num, &k_value, &k_ttl, inherit);
  if (!err)
    {
      err = rsbac_put_user(&k_value, value_p,
                           sizeof(k_value));
      if (!err && ttl_p)
        {
          err = rsbac_put_user(&k_ttl, ttl_p,
                               sizeof(k_ttl));
        }
    }
  return err;
}

static int sys_rsbac_res_set_user_limit(rsbac_list_ta_number_t ta_number,
				rsbac_uid_t uid,
				enum rsbac_attribute_t attr,
				rsbac_res_desc_t res_num,
				rsbac_res_limit_t __user * value_p,
				rsbac_time_t ttl)
{
  union rsbac_target_id_t k_tid;
  union rsbac_attribute_value_t k_attr_val;
  rsbac_res_limit_t k_value;
  int err;

  switch (attr)
    {
      case A_res_min:
      case A_res_max:
        break;
      default:
        return -RSBAC_EINVALIDATTR;
    }

#ifdef CONFIG_RSBAC_UM_VIRTUAL
  if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
    uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(uid));
  else
    if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
      return -RSBAC_EINVALIDVALUE;
#else
  uid = RSBAC_UID_NUM(uid);
#endif

  k_tid.user = uid;
  k_attr_val.dummy = 0;

  if (value_p) {
    err = rsbac_get_user(&k_value, value_p, sizeof(k_value));
    if(err < 0)
      return err;
  }

  /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "sys_rsbac_res_set_user_limit(): calling ADF\n");
    }
#endif
  if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                         task_pid(current),
                         T_USER,
                         k_tid,
                         attr,
                         k_attr_val))
    {
      return -EPERM;
    }

  return rsbac_ta_set_res_limit(ta_number, T_USER, &k_tid, attr, res_num, value_p ? &k_value : NULL, ttl);
}

static int sys_rsbac_res_get_file_limit(rsbac_list_ta_number_t ta_number,
				char __user * t_name,
				enum rsbac_attribute_t attr,
				rsbac_res_desc_t res_num,
				rsbac_res_limit_t __user * value_p,
				rsbac_time_t * ttl_p)
{
  union rsbac_target_id_t k_tid;
  union rsbac_attribute_value_t k_attr_val;
  rsbac_res_limit_t k_value;
  rsbac_time_t k_ttl;
  struct path path;
  int err;

  if (!t_name || !value_p)
    return -RSBAC_EINVALIDPOINTER;
  switch (attr)
    {
      case A_res_min:
      case A_res_max:
        break;
      default:
        return -RSBAC_EINVALIDATTR;
    }

  /* lookup filename */
  if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_get_file_limit(): call to user_path_at() returned %i\n", err);
        }
#endif
      return err;
    }
  if (!path.dentry->d_inode)
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_get_file_limit(): file not found\n");
        }
#endif
      err = -RSBAC_EINVALIDTARGET;
      goto out_dput;
    }

  if (!(S_ISREG(path.dentry->d_inode->i_mode)))
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_get_file_limit(): no file\n");
        }
#endif
      err = -RSBAC_EINVALIDTARGET;
      goto out_dput;
    }

  /* fill target id and call internal function */
  k_tid.file.device = path.dentry->d_sb->s_dev;
  k_tid.file.inode  = path.dentry->d_inode->i_ino;
  k_tid.file.dentry_p = path.dentry;
  k_attr_val.dummy = 0;

  /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "sys_rsbac_res_get_file_limit(): calling ADF\n");
    }
#endif
  if (!rsbac_adf_request(R_READ_ATTRIBUTE,
                         task_pid(current),
                         T_FILE,
                         k_tid,
                         attr,
                         k_attr_val))
    {
      err = -EPERM;
      goto out_dput;
    }

  err = rsbac_ta_get_res_limit(ta_number, T_FILE, &k_tid, attr, res_num, &k_value, &k_ttl, FALSE);
  if (!err)
    {
      err = rsbac_put_user(&k_value, value_p,
                           sizeof(k_value));
      if (!err && ttl_p)
        {
          err = rsbac_put_user(&k_ttl, ttl_p,
                               sizeof(k_ttl));
        }
    }

out_dput:
  path_put(&path);

  return err;
}

static int sys_rsbac_res_set_file_limit(rsbac_list_ta_number_t ta_number,
				char __user * t_name,
				enum rsbac_attribute_t attr,
				rsbac_res_desc_t res_num,
				rsbac_res_limit_t __user * value_p,
				rsbac_time_t ttl)
{
  union rsbac_target_id_t k_tid;
  union rsbac_attribute_value_t k_attr_val;
  struct path path;
  rsbac_res_limit_t k_value;
  int err;

  if (!t_name)
    return -RSBAC_EINVALIDPOINTER;
  switch (attr)
    {
      case A_res_min:
      case A_res_max:
        break;
      default:
        return -RSBAC_EINVALIDATTR;
    }

  if (value_p) {
    err = rsbac_get_user(&k_value, value_p, sizeof(k_value));
    if(err < 0)
      return err;
  }

  /* lookup filename */
  if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_set_file_limit(): call to user_path_at() returned %i\n", err);
        }
#endif
      return err;
    }
  if (!path.dentry->d_inode)
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_set_file_limit(): file not found\n");
        }
#endif
      err = -RSBAC_EINVALIDTARGET;
      goto out_dput;
    }

  if (!(S_ISREG(path.dentry->d_inode->i_mode)))
    {
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_res_set_file_limit(): no file\n");
        }
#endif
      err = -RSBAC_EINVALIDTARGET;
      goto out_dput;
    }

  /* fill target id and call internal function */
  k_tid.file.device = path.dentry->d_sb->s_dev;
  k_tid.file.inode  = path.dentry->d_inode->i_ino;
  k_tid.file.dentry_p = path.dentry;
  k_attr_val.dummy = 0;

  /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
  if (rsbac_debug_aef)
    {
      rsbac_printk(KERN_DEBUG "sys_rsbac_res_set_file_limit(): calling ADF\n");
    }
#endif
  if (!rsbac_adf_request(R_MODIFY_ATTRIBUTE,
                         task_pid(current),
                         T_FILE,
                         k_tid,
                         attr,
                         k_attr_val))
    {
      err = -EPERM;
      goto out_dput;
    }

  err = rsbac_ta_set_res_limit(ta_number, T_FILE, &k_tid, attr, res_num, value_p ? &k_value : NULL, ttl);

out_dput:
  path_put(&path);

  return err;
}
#endif

/**********************************/
/************** REG ***************/

#ifdef CONFIG_RSBAC_REG
static int sys_rsbac_reg(rsbac_reg_handle_t handle,
                             void __user * arg)
  {
    return rsbac_reg_syscall(handle, arg);
  }
#endif

/**********************************/
/************** ACL ***************/

#ifdef CONFIG_RSBAC_ACL
static int sys_rsbac_acl(
         rsbac_list_ta_number_t     ta_number,
  enum   rsbac_acl_syscall_type_t   call,
  struct rsbac_acl_syscall_arg_t __user * arg)
    { 
      struct rsbac_acl_syscall_arg_t k_arg;
      int   err = 0;
      
      if(call >= ACLC_none)
        return -RSBAC_EINVALIDREQUEST;
      if(!arg)
        return -RSBAC_EINVALIDPOINTER;

      /* get values from user space */
      err = rsbac_get_user(&k_arg, arg, sizeof(k_arg));
      if(err < 0)
        return err;

      if(k_arg.target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
/*      rsbac_printk(KERN_DEBUG "sys_rsbac_acl(): target = %u, call = %u, subj_type = %u, subj_id = %u!\n",
             k_arg.target, call, k_arg.subj_type, k_arg.subj_id); */

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_acl(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

      if(call != ACLC_set_mask)
        {
          switch(k_arg.subj_type)
            {
              case ACLS_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                if (RSBAC_UID_SET(k_arg.subj_id) == RSBAC_UM_VIRTUAL_KEEP)
                  k_arg.subj_id = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_arg.subj_id));
                else
                  if (RSBAC_UID_SET(k_arg.subj_id) > RSBAC_UM_VIRTUAL_MAX)
                    return -RSBAC_EINVALIDVALUE;
#else
                k_arg.subj_id = RSBAC_UID_NUM(k_arg.subj_id);
#endif
                break;
              case ACLS_GROUP:
                if(k_arg.subj_id != RSBAC_ACL_GROUP_EVERYONE)
                  {
                    struct rsbac_acl_group_entry_t entry;
                           rsbac_uid_t caller;

                    rsbac_get_owner(&caller);
                    if(   rsbac_acl_get_group_entry(ta_number, k_arg.subj_id, &entry)
                       || (   (entry.owner != caller)
                           && (entry.type != ACLG_GLOBAL)
                          )
                      )
                      return -RSBAC_EINVALIDVALUE;
                  }
                break;
              #if defined(CONFIG_RSBAC_RC)
              case ACLS_ROLE:
                if(k_arg.subj_id > RC_role_max_value)
                  {
                    rsbac_printk(KERN_DEBUG "sys_rsbac_acl(): Invalid role %u!\n", k_arg.subj_id);
                    return -RSBAC_EINVALIDVALUE;
                  }
                break;
              #endif
              default:
                rsbac_printk(KERN_DEBUG "sys_rsbac_acl(): Invalid subject type %u!\n", k_arg.subj_type);
                return -RSBAC_EINVALIDVALUE;
            }
          if(   (call == ACLC_remove_user)
             && (k_arg.target != T_USER)
            )
            return -RSBAC_EINVALIDTARGET;
          
        }
        
      /* call acl function */
      switch(call)
        {
          case ACLC_set_acl_entry:
            err = rsbac_acl_sys_set_acl_entry(ta_number,
                                              k_arg.target,
                                              k_arg.tid,
                                              k_arg.subj_type,
                                              k_arg.subj_id,
                                              k_arg.rights,
                                              k_arg.ttl);
            break;
          case ACLC_remove_acl_entry:
            err = rsbac_acl_sys_remove_acl_entry(ta_number,
                                                 k_arg.target,
                                                 k_arg.tid,
                                                 k_arg.subj_type,
                                                 k_arg.subj_id);
            break;
          case ACLC_remove_acl:
            err = rsbac_acl_sys_remove_acl(ta_number,
                                           k_arg.target,
                                           k_arg.tid);
            break;
          case ACLC_add_to_acl_entry:
            err = rsbac_acl_sys_add_to_acl_entry(ta_number,
                                                 k_arg.target,
                                                 k_arg.tid,
                                                 k_arg.subj_type,
                                                 k_arg.subj_id,
                                                 k_arg.rights,
                                                 k_arg.ttl);
            break;
          case ACLC_remove_from_acl_entry:
            err = rsbac_acl_sys_remove_from_acl_entry(ta_number,
                                                      k_arg.target,
                                                      k_arg.tid,
                                                      k_arg.subj_type,
                                                      k_arg.subj_id,
                                                      k_arg.rights);
            break;
          case ACLC_set_mask:
            err = rsbac_acl_sys_set_mask(ta_number,
                                         k_arg.target,
                                         k_arg.tid,
                                         k_arg.rights);
            break;
          case ACLC_remove_user:
            err = rsbac_acl_sys_remove_user(ta_number,
                                            k_arg.tid.user);
            break;

          default:
            err = -RSBAC_EINVALIDREQUEST;
        }
      return err;
    }      /* end of sys_rsbac_acl() */


static int sys_rsbac_acl_n(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_acl_syscall_type_t    call,
  struct rsbac_acl_syscall_n_arg_t __user * arg)
    {
      struct dentry * t_dentry = NULL;
      int     err = 0;
      union rsbac_target_id_t  tid;
      struct rsbac_acl_syscall_n_arg_t k_arg;

      struct path path;

      if(call >= ACLC_none)
        return -RSBAC_EINVALIDREQUEST;
      if(!arg)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_acl_n(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

      /* get values from user space */
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
      if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32)) {
        struct rsbac_acl_syscall_n_arg_ia32_t k_arg_ia32;

        err = rsbac_get_user(&k_arg_ia32, arg, sizeof(k_arg_ia32) );
        if(err < 0)
          return err;
        memset(&k_arg, 0, sizeof(k_arg));
        k_arg.target = k_arg_ia32.target;
        k_arg.name = (void __user *)(long)k_arg_ia32.name;
        k_arg.subj_type = k_arg_ia32.subj_type;
        k_arg.subj_id = k_arg_ia32.subj_id;
        k_arg.rights = k_arg_ia32.rights;
        k_arg.ttl = k_arg_ia32.ttl;
      } else {
#endif
        err = rsbac_get_user(&k_arg, arg, sizeof(k_arg) );
        if(err < 0)
          return err;
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
      }
#endif

      if(k_arg.target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
      if(call != ACLC_set_mask)
        {
          switch(k_arg.subj_type)
            {
              case ACLS_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                if (RSBAC_UID_SET(k_arg.subj_id) == RSBAC_UM_VIRTUAL_KEEP)
                  k_arg.subj_id = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_arg.subj_id));
                else
                  if (RSBAC_UID_SET(k_arg.subj_id) > RSBAC_UM_VIRTUAL_MAX)
                    return -RSBAC_EINVALIDVALUE;
#else
                k_arg.subj_id = RSBAC_UID_NUM(k_arg.subj_id);
#endif
                break;
              case ACLS_GROUP:
                if(k_arg.subj_id != RSBAC_ACL_GROUP_EVERYONE)
                  {
                    struct rsbac_acl_group_entry_t entry;
                           rsbac_uid_t caller;

                    rsbac_get_owner(&caller);
                    if(   rsbac_acl_get_group_entry(ta_number, k_arg.subj_id, &entry)
                       || (   (entry.owner != caller)
                           && (entry.type != ACLG_GLOBAL)
                          )
                      )
                      return -RSBAC_EINVALIDVALUE;
                  }
                break;
              #if defined(CONFIG_RSBAC_RC)
              case ACLS_ROLE:
                if(k_arg.subj_id > RC_role_max_value)
                  return -RSBAC_EINVALIDVALUE;
                break;
              #endif
              default:
                return -RSBAC_EINVALIDVALUE;
            }
        }
        
      if(k_arg.name)
        {
          /* lookup filename */
          if ((err = user_path_at(AT_FDCWD, k_arg.name, 0, &path)))
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef)
                rsbac_printk(KERN_DEBUG "sys_rsbac_acl_n(): call to user_path_at() returned %i\n", err);
#endif
              goto out;
            }
          t_dentry = path.dentry;
          if (!t_dentry->d_inode)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef)
                rsbac_printk(KERN_DEBUG "sys_rsbac_acl_n(): file not found\n");
#endif
              err = -RSBAC_EINVALIDTARGET;
              goto out_dput;
            }
          tid.file.device = t_dentry->d_sb->s_dev;
          tid.file.inode  = t_dentry->d_inode->i_ino;
          tid.file.dentry_p = t_dentry;
        }
      else
        {
          tid.file.device = RSBAC_ZERO_DEV;
          tid.file.inode  = 0;
          tid.file.dentry_p = NULL;
        }

      switch (k_arg.target)
        {
          case T_FD:
            if(k_arg.name)
              {
                if(S_ISREG(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_FILE;
                  }
                else
                if(S_ISDIR(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_DIR;
                  }
                else
                if(S_ISLNK(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_SYMLINK;
                  }
                else
                if(S_ISFIFO(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_FIFO;
                  }
                else
                if(S_ISSOCK(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_UNIXSOCK;
                  }
                else
                if(S_ISBLK(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_FILE;
                  }
                else
                if(S_ISCHR(t_dentry->d_inode->i_mode))
                  {
                    k_arg.target = T_FILE;
                  }
                else
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_n(): no filesystem object\n");
#endif
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            else
              k_arg.target = T_FILE;
            break;

          case T_FILE:
            if(k_arg.name)
              {
                /* is inode of type file, symlink or block/char device? */
                if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                    && !(S_ISBLK(t_dentry->d_inode->i_mode))
                    && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            break;

          case T_DIR:
            if(k_arg.name)
              {
                if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
                  { /* This is no dir */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            break;

          case T_FIFO:
            if(k_arg.name)
              {
                /* is inode of type fifo? */
                if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            break;

          case T_UNIXSOCK:
            if(k_arg.name)
              {
                /* is inode of type fifo? */
                if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            break;

          case T_SYMLINK:
            if(k_arg.name)
              {
                /* is inode of type symlink? */
                if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
              }
            break;

          case T_DEV:
            if(k_arg.name)
              {
                /* is inode of type block/char device? */
                if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                    && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* fill target id and call internal function */
                if(S_ISBLK(t_dentry->d_inode->i_mode))
                  tid.dev.type = D_block;
                else
                  tid.dev.type = D_char;
                tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
                tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
              }
            else
              {
                tid.dev = RSBAC_ZERO_DEV_DESC;
              }
            break;

          default:
            err = -RSBAC_EINVALIDTARGET;
            goto out_dput;
        }
      /* call acl function */
      switch(call)
        {
          case ACLC_set_acl_entry:
            err = rsbac_acl_sys_set_acl_entry(ta_number,
                                              k_arg.target,
                                              tid,
                                              k_arg.subj_type,
                                              k_arg.subj_id,
                                              k_arg.rights,
                                              k_arg.ttl);
            break;
          case ACLC_remove_acl_entry:
            err = rsbac_acl_sys_remove_acl_entry(ta_number,
                                                 k_arg.target,
                                                 tid,
                                                 k_arg.subj_type,
                                                 k_arg.subj_id);
            break;
          case ACLC_remove_acl:
            err = rsbac_acl_sys_remove_acl(ta_number,
                                           k_arg.target,
                                           tid);
            break;
          case ACLC_add_to_acl_entry:
            err = rsbac_acl_sys_add_to_acl_entry(ta_number,
                                                 k_arg.target,
                                                 tid,
                                                 k_arg.subj_type,
                                                 k_arg.subj_id,
                                                 k_arg.rights,
                                                 k_arg.ttl);
            break;
          case ACLC_remove_from_acl_entry:
            err = rsbac_acl_sys_remove_from_acl_entry(ta_number,
                                                      k_arg.target,
                                                      tid,
                                                      k_arg.subj_type,
                                                      k_arg.subj_id,
                                                      k_arg.rights);
            break;
          case ACLC_set_mask:
            err = rsbac_acl_sys_set_mask(ta_number,
                                         k_arg.target,
                                         tid,
                                         k_arg.rights);
            break;

          default:
            err = -RSBAC_EINVALIDREQUEST;
        }

out_dput:
      if(k_arg.name)
        {
          path_put(&path);
        }

out:
      return err;
    }      /* end of sys_rsbac_acl_n() */

/************************************************************************** */

static int sys_rsbac_acl_get_rights(
         rsbac_list_ta_number_t      ta_number,
  struct rsbac_acl_syscall_arg_t   __user * arg,
         rsbac_acl_rights_vector_t __user * rights_p,
         u_int                       effective)
    { 
      struct rsbac_acl_syscall_arg_t k_arg;
      rsbac_acl_rights_vector_t k_rights = 0;
      int   err = 0;
      
      if(!arg || !rights_p)
        return -RSBAC_EINVALIDPOINTER;
      /* get values from user space */
      rsbac_get_user(&k_arg, arg, sizeof(k_arg) );

      if(k_arg.target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
/*      printk(KERN_DEBUG "sys_rsbac_acl_get_rights(): target = %u, subj_type = %u, subj_id = %u!\n",
             k_arg.target, k_arg.subj_type, k_arg.subj_id); */
      switch(k_arg.subj_type)
        {
          case ACLS_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(k_arg.subj_id) == RSBAC_UM_VIRTUAL_KEEP)
              k_arg.subj_id = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_arg.subj_id));
            else
              if (RSBAC_UID_SET(k_arg.subj_id) > RSBAC_UM_VIRTUAL_MAX)
                return -RSBAC_EINVALIDVALUE;
#else
            k_arg.subj_id = RSBAC_UID_NUM(k_arg.subj_id);
#endif
            break;
          case ACLS_GROUP:
            if(k_arg.subj_id != RSBAC_ACL_GROUP_EVERYONE)
              {
                struct rsbac_acl_group_entry_t entry;
                       rsbac_uid_t caller;

                rsbac_get_owner(&caller);
                if(   rsbac_acl_get_group_entry(ta_number, k_arg.subj_id, &entry)
                   || (   (entry.owner != caller)
                       && (entry.type != ACLG_GLOBAL)
                      )
                  )
                  return -RSBAC_EINVALIDVALUE;
              }
            break;
          case ACLS_ROLE:
          #if defined(CONFIG_RSBAC_RC)
            if(k_arg.subj_id > RC_role_max_value)
              return -RSBAC_EINVALIDVALUE;
          #endif
            break;
          default:
            rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_rights(): Invalid subject type %u!\n", k_arg.subj_type);
            return -RSBAC_EINVALIDVALUE;
        }

      /* call acl function */
      err = rsbac_acl_sys_get_rights(ta_number,
                                     k_arg.target,
                                     k_arg.tid,
                                     k_arg.subj_type,
                                     k_arg.subj_id,
                                     &k_rights,
                                     effective);
      if(!err)
        {
          err = rsbac_put_user(&k_rights, rights_p, sizeof(k_rights) );
        }
      return err;
    }      /* end of sys_rsbac_acl_get_rights() */


static int sys_rsbac_acl_get_rights_n(
         rsbac_list_ta_number_t      ta_number,
  struct rsbac_acl_syscall_n_arg_t __user * arg,
         rsbac_acl_rights_vector_t __user * rights_p,
         u_int                       effective)
    {
      struct dentry * t_dentry = NULL;
      rsbac_boolean_t need_put = FALSE;
      int     err = 0;
      union rsbac_target_id_t  tid;
      struct rsbac_acl_syscall_n_arg_t k_arg;
      rsbac_acl_rights_vector_t k_rights = 0;
     
      struct path path;

      if(!arg || !rights_p)
        return -RSBAC_EINVALIDPOINTER;
      /* get values from user space */
      rsbac_get_user(&k_arg, arg, sizeof(k_arg) );

      if(k_arg.target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
      switch(k_arg.subj_type)
        {
          case ACLS_USER:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(k_arg.subj_id) == RSBAC_UM_VIRTUAL_KEEP)
              k_arg.subj_id = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(k_arg.subj_id));
            else
              if (RSBAC_UID_SET(k_arg.subj_id) > RSBAC_UM_VIRTUAL_MAX)
                return -RSBAC_EINVALIDVALUE;
#else
            k_arg.subj_id = RSBAC_UID_NUM(k_arg.subj_id);
#endif
            break;
          case ACLS_GROUP:
            if(k_arg.subj_id != RSBAC_ACL_GROUP_EVERYONE)
              {
                struct rsbac_acl_group_entry_t entry;
                       rsbac_uid_t caller;

                rsbac_get_owner(&caller);
                if(   rsbac_acl_get_group_entry(ta_number, k_arg.subj_id, &entry)
                   || (   (entry.owner != caller)
                       && (entry.type != ACLG_GLOBAL)
                      )
                  )
                  return -RSBAC_EINVALIDVALUE;
              }
            break;
          case ACLS_ROLE:
          #if defined(CONFIG_RSBAC_RC)
            if(k_arg.subj_id > RC_role_max_value)
              return -RSBAC_EINVALIDVALUE;
          #endif
            break;
          default:
            return -RSBAC_EINVALIDVALUE;
        }
        
      switch (k_arg.target)
        {
          case T_FD:
          case T_FILE:
          case T_DIR:
          case T_FIFO:
          case T_UNIXSOCK:
          case T_SYMLINK:
            if(k_arg.name)
              {
                if ((err = user_path_at(AT_FDCWD, k_arg.name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_rights_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type file, symlink or block/char device? */
                switch(k_arg.target)
                  {
                    case T_FD:
                      if(S_ISREG(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_FILE;
                        }
                      else
                      if(S_ISDIR(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_DIR;
                        }
                      else
                      if(S_ISLNK(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_SYMLINK;
                        }
                      else
                      if(S_ISFIFO(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_FIFO;
                        }
                      else
                      if(S_ISSOCK(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_UNIXSOCK;
                        }
                      else
                      if(S_ISBLK(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_FILE;
                        }
                      else
                      if(S_ISCHR(t_dentry->d_inode->i_mode))
                        {
                          k_arg.target = T_FILE;
                        }
                      else
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FILE:
                      if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                          && !(S_ISBLK(t_dentry->d_inode->i_mode))
                          && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_DIR:
                      if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
                        { /* This is no dir */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FIFO:
                      /* is inode of type fifo? */
                      if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
                        { /* This is no fifo */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_UNIXSOCK:
                      if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
                        {
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_SYMLINK:
                      /* is inode of type symlink? */
                      if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
                        { /* This is no symlink */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    default:
                      err = -RSBAC_EINVALIDTARGET;
                      goto out_dput;
                  }
                tid.file.device = t_dentry->d_sb->s_dev;
                tid.file.inode  = t_dentry->d_inode->i_ino;
                tid.file.dentry_p = t_dentry;
              }
            else
              {
                if(k_arg.target == T_FD)
                  k_arg.target = T_FILE;
                tid.file.device = RSBAC_ZERO_DEV;
                tid.file.inode  = 0;
                tid.file.dentry_p = NULL;
              }
            break;

          case T_DEV:
            if(k_arg.name)
              {
                if ((err = user_path_at(AT_FDCWD, k_arg.name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_rights_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type file, symlink or block/char device? */
                if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                    && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* fill target id and call internal function */
                if(S_ISBLK(t_dentry->d_inode->i_mode))
                  tid.dev.type = D_block;
                else
                  tid.dev.type = D_char;
                tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
                tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
              }
            else
              {
                tid.dev = RSBAC_ZERO_DEV_DESC;
              }
            break;

          default:
            return -RSBAC_EINVALIDTARGET;
        }

      /* call acl function */
      err = rsbac_acl_sys_get_rights(ta_number,
                                     k_arg.target,
                                     tid,
                                     k_arg.subj_type,
                                     k_arg.subj_id,
                                     &k_rights,
                                     effective);

out_dput:
      if(need_put)
        path_put(&path);
out:
      if(!err)
        {
          rsbac_put_user(&k_rights, rights_p, sizeof(k_rights) );
        }
      return err;
    }      /* end of sys_rsbac_acl_get_rights_n() */

/************************************************************************** */

static int sys_rsbac_acl_get_tlist (
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t  __user * tid,
  struct rsbac_acl_entry_t  __user   entry_array[],
         rsbac_time_t       __user   ttl_array[],
         u_int                       maxnum)
    { 
      union  rsbac_target_id_t   k_tid;
      struct rsbac_acl_entry_t * k_entry_p;
             rsbac_time_t      * k_ttl_p;
             int   err = 0;

      if(!tid || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!entry_array)
        return -RSBAC_EINVALIDPOINTER;
      if(!maxnum)
        return -RSBAC_EINVALIDVALUE;
      if(maxnum > RSBAC_ACL_MAX_MAXNUM)
        maxnum = RSBAC_ACL_MAX_MAXNUM;

      /* get values from user space */
      err = rsbac_get_user(&k_tid, tid, sizeof(k_tid) );
      if(unlikely(err < 0))
        return err;
      switch (target) {
              case T_FD:
                      return -RSBAC_EINVALIDTARGET;
              case T_FILE:
              case T_DIR:
              case T_FIFO:
              case T_UNIXSOCK:
              case T_SYMLINK:
                      k_tid.file.dentry_p = NULL;
                      k_tid.dir.dentry_p = NULL;
                      break;
              case T_PROCESS:
                      k_tid.process = find_pid_ns(k_tid.uprocess, &init_pid_ns);
                      if(!k_tid.process)
                        return -RSBAC_EINVALIDTARGET;
                      break;
              default:
                      break;
      }

      /* call acl function */
      err = rsbac_acl_sys_get_tlist(ta_number, target, k_tid, &k_entry_p, &k_ttl_p);
      if(err>0)
        {
          if(err > maxnum)
            err = maxnum;
          rsbac_put_user(k_entry_p,
                         entry_array,
                         err * sizeof(*k_entry_p) );
          if(ttl_array)
            {
              rsbac_put_user(k_ttl_p,
                             ttl_array,
                             err * sizeof(*k_ttl_p) );
            }
          rsbac_kfree(k_entry_p);
          rsbac_kfree(k_ttl_p);
        }
      return err;
    }      /* end of sys_rsbac_acl_get_tlist() */

static int sys_rsbac_acl_get_tlist_n(
         rsbac_list_ta_number_t   ta_number,
  enum   rsbac_target_t           target,
         char                     __user * t_name,
  struct rsbac_acl_entry_t        __user entry_array[],
         rsbac_time_t             __user ttl_array[],
         u_int                    maxnum)
    {
      struct dentry * t_dentry = NULL;
      struct rsbac_acl_entry_t * k_entry_p;
      rsbac_time_t * k_ttl_p;
      rsbac_boolean_t need_put = FALSE;
      int     err = 0;
      union rsbac_target_id_t  tid;
     
      struct path path;
        
      if(target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
      if(!entry_array)
        return -RSBAC_EINVALIDPOINTER;

      switch (target)
        {
          case T_FD:
          case T_FILE:
          case T_DIR:
          case T_FIFO:
          case T_UNIXSOCK:
          case T_SYMLINK:
            if(t_name)
              {
                if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_tlist_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type file, symlink or block/char device? */
                switch(target)
                  {
                    case T_FD:
                      if(S_ISREG(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                      if(S_ISDIR(t_dentry->d_inode->i_mode))
                        {
                          target = T_DIR;
                        }
                      else
                      if(S_ISLNK(t_dentry->d_inode->i_mode))
                        {
                          target = T_SYMLINK;
                        }
                      else
                      if(S_ISFIFO(t_dentry->d_inode->i_mode))
                        {
                          target = T_FIFO;
                        }
                      else
                      if(S_ISSOCK(t_dentry->d_inode->i_mode))
                        {
                          target = T_UNIXSOCK;
                        }
                      else
                      if(S_ISBLK(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                      if(S_ISCHR(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FILE:
                      if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                          && !(S_ISBLK(t_dentry->d_inode->i_mode))
                          && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_DIR:
                      if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
                        { /* This is no dir */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FIFO:
                      /* is inode of type fifo? */
                      if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
                        { /* This is no fifo */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_UNIXSOCK:
                      if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
                        {
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_SYMLINK:
                      /* is inode of type symlink? */
                      if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
                        { /* This is no symlink */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    default:
                      err = -RSBAC_EINVALIDTARGET;
                      goto out_dput;
                  }
                tid.file.device = t_dentry->d_sb->s_dev;
                tid.file.inode  = t_dentry->d_inode->i_ino;
                tid.file.dentry_p = t_dentry;
              }
            else
              {
                if(target == T_FD)
                  target = T_FILE;
                tid.file.device = RSBAC_ZERO_DEV;
                tid.file.inode  = 0;
                tid.file.dentry_p = NULL;
              }
            break;

          case T_DEV:
            if(t_name)
              {
                if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_tlist_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type file, symlink or block/char device? */
                if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                    && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* fill target id and call internal function */
                if(S_ISBLK(t_dentry->d_inode->i_mode))
                  tid.dev.type = D_block;
                else
                  tid.dev.type = D_char;
                tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
                tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
              }
            else
              {
                tid.dev = RSBAC_ZERO_DEV_DESC;
              }
            break;

          default:
            return -RSBAC_EINVALIDTARGET;
        }
      /* call ACL function */
      err = rsbac_acl_sys_get_tlist(ta_number, target, tid,
                                    &k_entry_p, &k_ttl_p);

out_dput:
      if(need_put)
        path_put(&path);
out:
      if(err>0)
        {
          if(err > maxnum)
            err = maxnum;
          rsbac_put_user(k_entry_p,
                         entry_array,
                         err * sizeof(*k_entry_p) );
          if(ttl_array)
            {
              rsbac_put_user(k_ttl_p,
                             ttl_array,
                             err * sizeof(*k_ttl_p) );
            }
          rsbac_kfree(k_entry_p);
          rsbac_kfree(k_ttl_p);
        }
      return err;
    }      /* end of sys_rsbac_acl_get_tlist_n() */

/************************************************************************** */

static int sys_rsbac_acl_get_mask (
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t         __user * tid,
         rsbac_acl_rights_vector_t __user * mask_p)
    { 
      union  rsbac_target_id_t k_tid;
             rsbac_acl_rights_vector_t k_mask;
             int   err = 0;
      
      if(!tid || (target >= T_NONE))
        return -RSBAC_EINVALIDTARGET;
      if(!mask_p)
        return -RSBAC_EINVALIDPOINTER;

      /* get values from user space */
      rsbac_get_user(&k_tid, tid, sizeof(k_tid) );
      switch (target) {
              case T_FD:
                      return -RSBAC_EINVALIDTARGET;
              case T_FILE:
              case T_DIR:
              case T_FIFO:
              case T_UNIXSOCK:
              case T_SYMLINK:
                      k_tid.file.dentry_p = NULL;
                      k_tid.dir.dentry_p = NULL;
                      break;
              case T_PROCESS:
                      k_tid.process = find_pid_ns(k_tid.uprocess, &init_pid_ns);
                      if(!k_tid.process)
                        return -RSBAC_EINVALIDTARGET;
                      break;
              default:
                      break;
      }
      /* call acl function */
      err = rsbac_acl_sys_get_mask(ta_number, target, k_tid, &k_mask);
      if(!err)
        {
          rsbac_put_user(&k_mask,
                         mask_p,
                         sizeof(k_mask) );
        }
      return err;
    }      /* end of sys_rsbac_acl_get_mask() */

static int sys_rsbac_acl_get_mask_n(
       rsbac_list_ta_number_t      ta_number,
  enum rsbac_target_t              target,
       char                        __user * t_name,
       rsbac_acl_rights_vector_t   __user * mask_p)
    {
      struct dentry * t_dentry = NULL;
      rsbac_acl_rights_vector_t k_mask;
      rsbac_boolean_t need_put = FALSE;
      int     err = 0;
      union rsbac_target_id_t  tid;

      struct path path;

      if(target >= T_NONE)
        return -RSBAC_EINVALIDTARGET;
      if(!mask_p)
        return -RSBAC_EINVALIDPOINTER;

      switch (target)
        {
          case T_FD:
          case T_FILE:
          case T_DIR:
          case T_FIFO:
          case T_UNIXSOCK:
          case T_SYMLINK:
            if(t_name)
              {
                if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_mask_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type file, symlink or block/char device? */
                switch(target)
                  {
                    case T_FD:
                      if(S_ISREG(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                      if(S_ISDIR(t_dentry->d_inode->i_mode))
                        {
                          target = T_DIR;
                        }
                      else
                      if(S_ISLNK(t_dentry->d_inode->i_mode))
                        {
                          target = T_SYMLINK;
                        }
                      else
                      if(S_ISFIFO(t_dentry->d_inode->i_mode))
                        {
                          target = T_FIFO;
                        }
                      else
                      if(S_ISSOCK(t_dentry->d_inode->i_mode))
                        {
                          target = T_UNIXSOCK;
                        }
                      else
                      if(S_ISBLK(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                      if(S_ISCHR(t_dentry->d_inode->i_mode))
                        {
                          target = T_FILE;
                        }
                      else
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FILE:
                      if (   !(S_ISREG(t_dentry->d_inode->i_mode))
                          && !(S_ISBLK(t_dentry->d_inode->i_mode))
                          && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                        { /* This is no file or device */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_DIR:
                      if ( !(S_ISDIR(t_dentry->d_inode->i_mode)) )
                        { /* This is no dir */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_FIFO:
                      if (   !(S_ISFIFO(t_dentry->d_inode->i_mode)))
                        { /* This is no fifo */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_UNIXSOCK:
                      if (   !(S_ISSOCK(t_dentry->d_inode->i_mode)))
                        {
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    case T_SYMLINK:
                      if (   !(S_ISLNK(t_dentry->d_inode->i_mode)))
                        { /* This is no symlink */
                          err = -RSBAC_EINVALIDTARGET;
                          goto out_dput;
                        }
                      break;
                    default:
                      err = -RSBAC_EINVALIDTARGET;
                      goto out_dput;
                  }
                tid.file.device = t_dentry->d_sb->s_dev;
                tid.file.inode  = t_dentry->d_inode->i_ino;
                tid.file.dentry_p = t_dentry;
              }
            else
              {
                if(target == T_FD)
                  target = T_FILE;
                tid.file.device = RSBAC_ZERO_DEV;
                tid.file.inode  = 0;
                tid.file.dentry_p = NULL;
              }
            break;

          case T_DEV:
            if(t_name)
              {
                if ((err = user_path_at(AT_FDCWD, t_name, 0, &path)))
                  {
#ifdef CONFIG_RSBAC_DEBUG
                    if (rsbac_debug_aef_acl)
                      rsbac_printk(KERN_DEBUG "sys_rsbac_acl_get_mask_n(): call to user_path_at() returned %i\n", err);
#endif
                    goto out;
                   }
                t_dentry = path.dentry;
                need_put = TRUE;
                if (!t_dentry->d_inode)
                  {
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* is inode of type block/char device? */
                if (   !(S_ISBLK(t_dentry->d_inode->i_mode))
                    && !(S_ISCHR(t_dentry->d_inode->i_mode)) )
                  { /* This is no file or device */
                    err = -RSBAC_EINVALIDTARGET;
                    goto out_dput;
                  }
                /* fill target id and call internal function */
                if(S_ISBLK(t_dentry->d_inode->i_mode))
                  tid.dev.type = D_block;
                else
                  tid.dev.type = D_char;
                tid.dev.major = RSBAC_MAJOR(t_dentry->d_inode->i_rdev);
                tid.dev.minor = RSBAC_MINOR(t_dentry->d_inode->i_rdev);
              }
            else
              {
                tid.dev = RSBAC_ZERO_DEV_DESC;
              }
            break;

          default:
            return -RSBAC_EINVALIDTARGET;
        }
      /* call ACL function */
      err = rsbac_acl_sys_get_mask(ta_number, target, tid, &k_mask);

out_dput:
      if(need_put)
        path_put(&path);
out:
      if(!err)
        {
          rsbac_put_user(&k_mask,
                         mask_p,
                         sizeof(k_mask) );
        }
      return err;
    }      /* end of sys_rsbac_acl_get_mask_n() */

/********  ACL groups *********/

static int sys_rsbac_acl_group(
        rsbac_list_ta_number_t           ta_number,
  enum  rsbac_acl_group_syscall_type_t   call,
  union rsbac_acl_group_syscall_arg_t __user * arg_p)
    { 
      union rsbac_acl_group_syscall_arg_t k_arg;
      int   err = 0;

      if(call >= ACLGS_none)
        return -RSBAC_EINVALIDREQUEST;
      if(!arg_p)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          switch(call)
            {
              case ACLGS_add_group:
              case ACLGS_change_group:
              case ACLGS_remove_group:
              case ACLGS_add_member:
              case ACLGS_remove_member:
                rsbac_printk(KERN_WARNING
                             "sys_rsbac_acl_group(): RSBAC configuration frozen, no administration allowed!\n");
                return -EPERM;

              default:
                break;
            }
        }
#endif

      /* get values from user space */
      err = rsbac_get_user(&k_arg, arg_p, sizeof(k_arg) );

      /* call acl function */
      if(err >= 0)
        err = rsbac_acl_sys_group(ta_number, call, k_arg);
      return err;
    }      /* end of sys_rsbac_acl() */

static int sys_rsbac_acl_list_all_dev(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_dev_desc_t __user * id_p,
  u_long maxnum)
  {
    int err = 0;
    long count;
    long count2;

    if(id_p && maxnum)
      {
        struct rsbac_dev_desc_t * k_id_p = NULL;

        count = rsbac_acl_list_all_major_dev(ta_number, &k_id_p);
        if(count < 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        if(count)
          {
            err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );
            rsbac_kfree(k_id_p);
            if(unlikely(err < 0))
              return err;
            id_p += count;
            maxnum -= count;
            if(!maxnum)
              return count;
          }

        count2 = rsbac_acl_list_all_dev(ta_number, &k_id_p);
        if(count2 < 0)
          return count2;
        if(count2 > maxnum)
          count2 = maxnum;

        if(count2)
          {
            err = rsbac_put_user(k_id_p, id_p, count2 * sizeof(*k_id_p) );
            rsbac_kfree(k_id_p);
            if(unlikely(err < 0))
              return err;
            count += count2;
          }
        return count;
      }
    else
      {
        count = rsbac_acl_list_all_major_dev(ta_number, NULL);
        if(count < 0)
          return count;
        count2 = rsbac_acl_list_all_dev(ta_number, NULL);
        if(count2 < 0)
          return count2;
        else
          return count + count2;
      }
  }

static int sys_rsbac_acl_list_all_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t __user * id_p,
  u_long maxnum)
  {
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        rsbac_uid_t * k_id_p = NULL;

        count = rsbac_acl_list_all_user(ta_number, &k_id_p);
        if(count < 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        if(count)
          {
            err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );
            rsbac_kfree(k_id_p);
            if(unlikely(err < 0))
              return err;
          }
        return count;
      }
    else
      {
        return rsbac_acl_list_all_user(ta_number, NULL);
      }
  }

static int sys_rsbac_acl_list_all_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t __user * id_p,
  u_long maxnum)
  {
#ifdef CONFIG_RSBAC_ACL_UM_PROT
    int err = 0;
    long count;

    if(id_p && maxnum)
      {
        rsbac_gid_t * k_id_p = NULL;

        count = rsbac_acl_list_all_group(ta_number, &k_id_p);
        if(count < 0)
          return count;
        if(count > maxnum)
          count = maxnum;

        if(count)
          {
            err = rsbac_put_user(k_id_p, id_p, count * sizeof(*k_id_p) );
            rsbac_kfree(k_id_p);
            if(unlikely(err < 0))
              return err;
          }
        return count;
      }
    else
      {
        return rsbac_acl_list_all_group(ta_number, NULL);
      }
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
  }
#endif

/********  UM *********/

#ifdef CONFIG_RSBAC_UM
static int sys_rsbac_um_auth_name(
  char __user * name,
  char __user * pass)
    { 
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      int err;
      char * k_name;
      char * k_pass;
      union rsbac_target_id_t i_tid;
      union rsbac_attribute_value_t i_attr_val;

      if(!name || !pass)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_name(): NULL name or pass\n");
            }
#endif
          return -RSBAC_EINVALIDPOINTER;
        }
      k_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_name)
        return -RSBAC_ENOMEM;
      k_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_pass)
        {
          rsbac_kfree(k_name);
          return -RSBAC_ENOMEM;
        }
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        goto out_free;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
      err = strncpy_from_user(k_pass, pass, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        goto out_free;
      k_pass[RSBAC_MAXNAMELEN-1] = 0;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_name(): authenticating user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      if(err) {
        if(err == -RSBAC_ENOTFOUND) {
          err = -EPERM;
          ssleep(1);
        }
        goto out_free;
      }

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_name(): calling ADF\n");
      }
#endif
    i_tid.user = uid;
    i_attr_val.dummy = 0;
    if (!rsbac_adf_request(R_AUTHENTICATE,
                           task_pid(current),
                           T_USER,
                           i_tid,
                           A_none,
                           i_attr_val))
      {
        err = -EPERM;
        ssleep(1);
        goto out_free;
      }

      err = rsbac_um_check_pass(uid, k_pass);
      if(err) {
        if(err == -RSBAC_ENOTFOUND) {
          err = -EPERM;
        }
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_um)
          {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	    if(RSBAC_UID_SET(uid))
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u/%u failed\n",
                           RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
            else
#endif
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u failed\n",
                           RSBAC_UID_NUM(uid));
        }
#endif
	ssleep(1);
        goto out_free;
      }

#ifdef CONFIG_RSBAC_AUTH
      /* set auth_last_auth for this process */
      i_tid.process = task_pid(current);
      i_attr_val.auth_last_auth = uid;
      if (rsbac_set_attr(SW_AUTH,
                         T_PROCESS,
                         i_tid,
                         A_auth_last_auth,
                         i_attr_val))
        {
          rsbac_ds_set_error("sys_rsbac_um_auth_name()", A_auth_last_auth);
        }
#endif /* AUTH */
#ifdef CONFIG_RSBAC_UM_VIRTUAL
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_name(): setting process %u vset to %u\n",
                       current->pid, RSBAC_UID_SET(uid));
      }
#endif
      /* set vset for this process */
      i_tid.process = task_pid(current);
      i_attr_val.vset = RSBAC_UID_SET(uid);
      if (rsbac_set_attr(SW_GEN,
                         T_PROCESS,
                         i_tid,
                         A_vset,
                         i_attr_val))
        {
          rsbac_ds_set_error("sys_rsbac_um_auth_name()", A_vset);
        }
#endif

out_free:
      rsbac_kfree(k_name);
      memset(k_pass, 0, RSBAC_MAXNAMELEN);
      rsbac_kfree(k_pass);
      return err;
    }

static int sys_rsbac_um_auth_uid(rsbac_uid_t uid,
                          char __user * pass)
    { 
      int err;
      char * k_pass;
      union rsbac_target_id_t i_tid;
      union rsbac_attribute_value_t i_attr_val;

      if(!pass)
        return -RSBAC_EINVALIDPOINTER;
      k_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_pass)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_pass, pass, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        goto out_free;
      k_pass[RSBAC_MAXNAMELEN-1] = 0;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if(RSBAC_UID_SET(uid))
            rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u/%u\n",
                       RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
          else
#endif
            rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u\n",
                       RSBAC_UID_NUM(uid));
      }
#endif
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): calling ADF\n");
      }
#endif
    i_tid.user = uid;
    i_attr_val.dummy = 0;
    if (!rsbac_adf_request(R_AUTHENTICATE,
                           task_pid(current),
                           T_USER,
                           i_tid,
                           A_none,
                           i_attr_val))
      {
        err = -EPERM;
        ssleep(1);
        goto out_free;
      }

      err = rsbac_um_check_pass(uid, k_pass);
      if(err) {
        if(err == -RSBAC_ENOTFOUND) {
          err = -EPERM;
        }
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_um)
          {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
	    if(RSBAC_UID_SET(uid))
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u/%u failed\n",
                           RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
            else
#endif
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_uid(): authenticating user %u failed\n",
                           RSBAC_UID_NUM(uid));
        }
#endif
        goto out_free;
      }

#ifdef CONFIG_RSBAC_AUTH
      /* set auth_last_auth for this process */
      i_tid.process = task_pid(current);
      i_attr_val.auth_last_auth = uid;
      if (rsbac_set_attr(SW_AUTH,
                         T_PROCESS,
                         i_tid,
                         A_auth_last_auth,
                         i_attr_val))
        {
          rsbac_ds_set_error("sys_rsbac_um_auth_uid()", A_auth_last_auth);
        }
#endif /* AUTH */
#ifdef CONFIG_RSBAC_UM_VIRTUAL
      /* set vset for this process */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_auth_name(): setting process %u vset to %u\n",
                       current->pid, RSBAC_UID_SET(uid));
      }
#endif
      i_tid.process = task_pid(current);
      i_attr_val.vset = RSBAC_UID_SET(uid);
      if (rsbac_set_attr(SW_GEN,
                         T_PROCESS,
                         i_tid,
                         A_vset,
                         i_attr_val))
        {
          rsbac_ds_set_error("sys_rsbac_um_auth_uid()", A_vset);
        }
#endif

out_free:
      memset(k_pass, 0, RSBAC_MAXNAMELEN);
      rsbac_kfree(k_pass);
      return err;
    }

static int sys_rsbac_um_add_user_hash(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  struct rsbac_um_user_entry_t __user * entry_p,
  char __user * pass,
  const char __user * hash_algo,
  rsbac_time_t ttl)
    { 
      int err;
      struct rsbac_um_user_entry_t * k_entry_p;
      char * k_pass;
      char * k_hash_algo;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_target_id_t       rsbac_new_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(!entry_p)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE_UM
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_um_add_user(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_user(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_CREATE,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      k_entry_p = rsbac_kmalloc_unlocked(sizeof(*k_entry_p));
      if(!k_entry_p)
        return -RSBAC_ENOMEM;
      if(pass)
        {
          k_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_pass)
            {
              rsbac_kfree(k_entry_p);
              return -RSBAC_ENOMEM;
            }
        }
      else
        k_pass = NULL;
      if(hash_algo)
        {
          k_hash_algo = rsbac_kmalloc_unlocked(RSBAC_UM_ALGO_NAME_LEN);
          if(!k_hash_algo)
            {
              rsbac_kfree(k_entry_p);
              if (k_pass)
                rsbac_kfree(k_pass);
              return -RSBAC_ENOMEM;
            }
        }
      else
        k_hash_algo = NULL;
      err = rsbac_get_user(k_entry_p, entry_p, sizeof(*k_entry_p));
      if(unlikely(err < 0))
        goto out_free;
      if(!k_entry_p->name[0])
        {
          err = -RSBAC_EINVALIDVALUE;
          goto out_free;
        }
      k_entry_p->name[RSBAC_UM_NAME_LEN - 1] = 0;
      k_entry_p->fullname[RSBAC_UM_FULLNAME_LEN - 1] = 0;
      k_entry_p->homedir[RSBAC_UM_HOMEDIR_LEN - 1] = 0;
      k_entry_p->shell[RSBAC_UM_SHELL_LEN - 1] = 0;
      err = rsbac_um_get_uid(0, k_entry_p->name, &uid);
      if(!err) {
        err = -RSBAC_EEXISTS;
        goto out_free;
      }
      if(pass)
        {
          err = strncpy_from_user(k_pass, pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            goto out_free;
          k_pass[RSBAC_MAXNAMELEN-1] = 0;
        }
      if(hash_algo)
        {
          err = strncpy_from_user(k_hash_algo, hash_algo, RSBAC_UM_ALGO_NAME_LEN);
          if(unlikely(err < 0))
            goto out_free;
          k_hash_algo[RSBAC_UM_ALGO_NAME_LEN-1] = 0;
        }
      err = rsbac_um_add_user(ta_number, &uid, k_entry_p, k_pass, k_hash_algo, ttl);

      /* RSBAC: notify ADF of new user */
      if(!err)
        {
          rsbac_target_id.user = uid;
          rsbac_new_target_id.dummy = 0;
          if (rsbac_adf_set_attr(R_CREATE,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 T_NONE,
                                 rsbac_new_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_add_user(): rsbac_adf_set_attr() returned error\n");
            }
        }

out_free:
      rsbac_kfree(k_entry_p);
      if(k_pass)
        {
          memset(k_pass, 0, RSBAC_MAXNAMELEN);
          rsbac_kfree(k_pass);
        }
      if(k_hash_algo)
        {
          rsbac_kfree(k_hash_algo);
        }
      return err;
    }

static int sys_rsbac_um_add_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  struct rsbac_um_user_entry_t __user * entry_p,
  char __user * pass,
  rsbac_time_t ttl)
    {
      return sys_rsbac_um_add_user_hash(ta_number, uid, entry_p, pass, NULL, ttl);
    }

static int sys_rsbac_um_add_group_hash(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  struct rsbac_um_group_entry_t __user * entry_p,
  char __user * pass,
  const char __user * hash_algo,
  rsbac_time_t ttl)
    { 
      int err;
      struct rsbac_um_group_entry_t * k_entry_p;
      char * k_pass;
      char * k_hash_algo;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_target_id_t       rsbac_new_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

    if(!entry_p)
      return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_add_group(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(gid));
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_group(): calling ADF\n");
      }
#endif
    rsbac_target_id.group = gid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_CREATE,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      k_entry_p = rsbac_kmalloc_unlocked(sizeof(*k_entry_p));
      if(!k_entry_p)
        return -RSBAC_ENOMEM;
      if(pass)
        {
          k_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_pass)
            {
              rsbac_kfree(k_entry_p);
              return -RSBAC_ENOMEM;
            }
        }
      else
        k_pass = NULL;
      if(hash_algo)
        {
          k_hash_algo = rsbac_kmalloc_unlocked(RSBAC_UM_ALGO_NAME_LEN);
          if(!k_hash_algo)
            {
              rsbac_kfree(k_entry_p);
              if (k_pass)
                rsbac_kfree(k_pass);
              return -RSBAC_ENOMEM;
            }
        }
      else
        k_hash_algo = NULL;
      err = rsbac_get_user(k_entry_p, entry_p, sizeof(*k_entry_p));
      if(unlikely(err < 0))
        goto out_free;
      if(!k_entry_p->name[0])
        {
          err = -RSBAC_EINVALIDVALUE;
          goto out_free;
        }
      k_entry_p->name[RSBAC_UM_NAME_LEN - 1] = 0;
      err = rsbac_um_get_gid(0, k_entry_p->name, &gid);
      if(!err) {
        err = -RSBAC_EEXISTS;
        goto out_free;
      }
      if(pass)
        {
          err = strncpy_from_user(k_pass, pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            goto out_free;
          k_pass[RSBAC_MAXNAMELEN-1] = 0;
        }
      err = rsbac_um_add_group(ta_number, &gid, k_entry_p, k_pass, k_hash_algo, ttl);

      /* RSBAC: notify ADF of new group */
      if(!err)
        {
          rsbac_target_id.group = gid;
          rsbac_new_target_id.dummy = 0;
          if (rsbac_adf_set_attr(R_CREATE,
                                 task_pid(current),
                                 T_GROUP,
                                 rsbac_target_id,
                                 T_NONE,
                                 rsbac_new_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_add_group(): rsbac_adf_set_attr() returned error\n");
            }
        }

out_free:
      rsbac_kfree(k_entry_p);
      if(k_pass)
        {
          memset(k_pass, 0, RSBAC_MAXNAMELEN);
          rsbac_kfree(k_pass);
        }
      if(k_hash_algo)
        {
          rsbac_kfree(k_hash_algo);
        }
      return err;
    }

static int sys_rsbac_um_add_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  struct rsbac_um_group_entry_t __user * entry_p,
  char __user * pass,
  rsbac_time_t ttl)
    {
      return sys_rsbac_um_add_group_hash(ta_number, gid, entry_p, pass, NULL, ttl); 
    }

static int sys_rsbac_um_add_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t group,
  rsbac_time_t ttl)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_add_gm(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(user) == RSBAC_UM_VIRTUAL_KEEP)
        user = RSBAC_GEN_UID (rsbac_get_vset(), user);
      else
        if (RSBAC_UID_SET(user) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      user = RSBAC_UID_NUM(user);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_gm(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = user;
    rsbac_attribute_value.group = group;
    if (!rsbac_adf_request(R_CHANGE_GROUP,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_group,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    return rsbac_um_add_gm(ta_number, user, group, ttl);
  }

static int sys_rsbac_um_mod_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t __user * data_p)
    { 
      int err;
      union rsbac_um_mod_data_t * k_data_p;
      enum  rsbac_adf_request_t     rsbac_request;
      union rsbac_target_id_t       rsbac_target_id;
      enum  rsbac_attribute_t       rsbac_attribute = A_none;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(mod >= UM_none)
        return -RSBAC_EINVALIDREQUEST;
      if(   !data_p
         && (mod != UM_pass)
         && (mod != UM_pass_algo)
        )
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_mod_user(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

      if(data_p)
        {
          k_data_p = rsbac_kmalloc_unlocked(sizeof(*k_data_p));
          if(!k_data_p)
            return -RSBAC_ENOMEM;
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
          if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32))
              err = rsbac_get_user(k_data_p, data_p, sizeof(union rsbac_um_mod_data_ia32_t));
          else
#endif
              err = rsbac_get_user(k_data_p, data_p, sizeof(*k_data_p));
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_data_p);
              return err;
            }
          k_data_p->string[RSBAC_MAXNAMELEN-1] = 0;
        }
      else
        k_data_p = NULL;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_mod_user(): calling ADF\n");
      }
#endif
    rsbac_attribute_value.dummy = 0;
    switch(mod)
      {
        case UM_name:
          rsbac_request = R_RENAME;
          break;

        case UM_pass:
        case UM_pass_algo:
        case UM_cryptpass:
        case UM_cryptpass_algo:
          rsbac_request = R_MODIFY_PERMISSIONS_DATA;
          break;

        case UM_fullname:
          rsbac_request = R_WRITE;
          break;

        case UM_homedir:
          rsbac_request = R_WRITE;
          break;

        case UM_shell:
          rsbac_request = R_WRITE;
          break;

        case UM_group:
          rsbac_request = R_CHANGE_GROUP;
          if (!k_data_p)
            return -RSBAC_EINVALIDPOINTER;
          rsbac_attribute = A_group;
          rsbac_attribute_value.group = k_data_p->group;
          break;

        case UM_lastchange:
          rsbac_request = R_WRITE;
          break;

        case UM_minchange:
          rsbac_request = R_WRITE;
          break;

        case UM_maxchange:
          rsbac_request = R_WRITE;
          break;

        case UM_warnchange:
          rsbac_request = R_WRITE;
          break;

        case UM_inactive:
          rsbac_request = R_WRITE;
          break;

        case UM_expire:
          rsbac_request = R_WRITE;
          break;

        case UM_ttl:
          rsbac_request = R_DELETE;
          break;

        default:
          if(k_data_p)
            rsbac_kfree(k_data_p);
          return -RSBAC_EINVALIDREQUEST;
      }
    rsbac_target_id.user = uid;
    if (!rsbac_adf_request(rsbac_request,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           rsbac_attribute,
                           rsbac_attribute_value))
      {
        if(k_data_p)
          rsbac_kfree(k_data_p);
        return -EPERM;
      }

      err = rsbac_um_mod_user(ta_number, uid, mod, k_data_p);

      if(k_data_p)
        rsbac_kfree(k_data_p);
      return err;
    }

static int sys_rsbac_um_mod_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t __user * data_p)
    { 
      int err;
      union rsbac_um_mod_data_t * k_data_p;
      enum  rsbac_adf_request_t     rsbac_request;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(mod >= UM_none)
        return -RSBAC_EINVALIDREQUEST;
      if(   !data_p
         && (mod != UM_pass)
         && (mod != UM_pass_algo)
        )
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_mod_group(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(gid));
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_mod_group(): calling ADF\n");
      }
#endif
    switch(mod)
      {
        case UM_name:
          rsbac_request = R_RENAME;
          break;

        case UM_pass:
        case UM_cryptpass:
        case UM_pass_algo:
        case UM_cryptpass_algo:
          rsbac_request = R_MODIFY_PERMISSIONS_DATA;
          break;

        case UM_ttl:
          rsbac_request = R_DELETE;
          break;

        default:
          return -RSBAC_EINVALIDREQUEST;
      }
    rsbac_target_id.group = gid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(rsbac_request,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      if(data_p)
        {
          k_data_p = rsbac_kmalloc_unlocked(sizeof(*k_data_p));
          if(!k_data_p)
            return -RSBAC_ENOMEM;
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
          if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32))
              err = rsbac_get_user(k_data_p, data_p, sizeof(union rsbac_um_mod_data_ia32_t));
          else
#endif
            err = rsbac_get_user(k_data_p, data_p, sizeof(*k_data_p));
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_data_p);
              return err;
            }
          k_data_p->string[RSBAC_MAXNAMELEN-1] = 0;
        }
      else
        k_data_p = NULL;

      err = rsbac_um_mod_group(ta_number, gid, mod, k_data_p);

      if(k_data_p)
        rsbac_kfree(k_data_p);
      return err;
    }

static int sys_rsbac_um_get_user_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t __user * data_p)
    { 
      int err;
      union rsbac_um_mod_data_t * k_data_p;
      enum  rsbac_adf_request_t     rsbac_request;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(mod >= UM_none)
        return -RSBAC_EINVALIDREQUEST;
      if(!data_p)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_user_item(): calling ADF\n");
      }
#endif
    rsbac_attribute_value.dummy = 0;
    switch(mod)
      {
        case UM_name:
          rsbac_request = R_SEARCH;
          break;

        case UM_group:
        case UM_fullname:
        case UM_homedir:
        case UM_shell:
          rsbac_request = R_GET_STATUS_DATA;
          break;

        case UM_pass:
        case UM_pass_algo:
          rsbac_request = R_GET_PERMISSIONS_DATA;
          break;

        case UM_lastchange:
        case UM_minchange:
        case UM_maxchange:
        case UM_warnchange:
        case UM_inactive:
        case UM_expire:
        case UM_ttl:
          rsbac_request = R_READ;
          break;

        default:
          return -RSBAC_EINVALIDREQUEST;
      }
    rsbac_target_id.user = uid;
    if (!rsbac_adf_request(rsbac_request,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      k_data_p = rsbac_kmalloc_unlocked(sizeof(*k_data_p));
      if(!k_data_p)
        return -RSBAC_ENOMEM;
      memset(k_data_p, 0, sizeof(*k_data_p));

      err = rsbac_um_get_user_item(ta_number, uid, mod, k_data_p);
      if(!err)
        {
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
          if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32))
              err = rsbac_put_user(k_data_p, data_p, sizeof(union rsbac_um_mod_data_ia32_t) );
          else
#endif
            err = rsbac_put_user(k_data_p, data_p, sizeof(*k_data_p) );
        }
      rsbac_kfree(k_data_p);
      return err;
    }

static int sys_rsbac_um_get_group_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t __user * data_p)
    { 
      int err;
      union rsbac_um_mod_data_t * k_data_p;
      enum  rsbac_adf_request_t     rsbac_request;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(mod >= UM_none)
        return -RSBAC_EINVALIDREQUEST;
      if(!data_p)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), gid);
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_group_item(): getting item %u for %u/%u\n",
                       mod, RSBAC_GID_SET(gid), RSBAC_GID_NUM(gid));
        }
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_group_item(): calling ADF\n");
      }
#endif
    rsbac_attribute_value.dummy = 0;
    switch(mod)
      {
        case UM_name:
          rsbac_request = R_SEARCH;
          break;

        case UM_pass:
        case UM_pass_algo:
          rsbac_request = R_GET_PERMISSIONS_DATA;
          break;

        case UM_ttl:
          rsbac_request = R_GET_STATUS_DATA;
          break;

        default:
          return -RSBAC_EINVALIDREQUEST;
      }
    rsbac_target_id.group = gid;
    if (!rsbac_adf_request(rsbac_request,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      k_data_p = rsbac_kmalloc_unlocked(sizeof(*k_data_p));
      if(!k_data_p)
        return -RSBAC_ENOMEM;
      memset(k_data_p, 0, sizeof(*k_data_p));

      err = rsbac_um_get_group_item(ta_number, gid, mod, k_data_p);
      if(!err)
        {
#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
          if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32))
            err = rsbac_put_user(k_data_p, data_p, sizeof(union rsbac_um_mod_data_ia32_t) );
          else
#endif
            err = rsbac_put_user(k_data_p, data_p, sizeof(*k_data_p) );
        }
      rsbac_kfree(k_data_p);
      return err;
    }

static int sys_rsbac_um_remove_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid)
  { 
    int err;
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_target_id_t       rsbac_new_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_remove_user(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_user(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_DELETE,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    err = rsbac_um_remove_user(ta_number, uid);

    if(!err)
      {
        rsbac_new_target_id.dummy = 0;
        if (rsbac_adf_set_attr(R_DELETE,
                               task_pid(current),
                               T_USER,
                               rsbac_target_id,
                               T_NONE,
                               rsbac_new_target_id,
                               A_none,
                               rsbac_attribute_value))
          {
            rsbac_printk(KERN_WARNING
                         "sys_rsbac_um_remove_user(): rsbac_adf_set_attr() returned error");
          }
      }

    return err;
  }

static int sys_rsbac_um_remove_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid)
  { 
    int err;
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_target_id_t       rsbac_new_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_remove_group(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), gid);
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_group(): calling ADF\n");
      }
#endif
    rsbac_target_id.group = gid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_DELETE,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    err = rsbac_um_remove_group(ta_number, gid);

    if(!err)
      {
        rsbac_new_target_id.dummy = 0;
        if (rsbac_adf_set_attr(R_DELETE,
                               task_pid(current),
                               T_GROUP,
                               rsbac_target_id,
                               T_NONE,
                               rsbac_new_target_id,
                               A_none,
                               rsbac_attribute_value))
          {
            rsbac_printk(KERN_WARNING
                         "sys_rsbac_um_remove_group(): rsbac_adf_set_attr() returned error");
          }
      }

    return err;
  }

static int sys_rsbac_um_remove_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t group)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
    if(rsbac_freeze)
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_um_remove_gm(): RSBAC configuration frozen, no administration allowed!\n");
        return -EPERM;
      }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(user) == RSBAC_UM_VIRTUAL_KEEP)
        user = RSBAC_GEN_UID (rsbac_get_vset(), user);
      else
        if (RSBAC_UID_SET(user) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      user = RSBAC_UID_NUM(user);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_gm(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = user;
    rsbac_attribute_value.group = group;
    if (!rsbac_adf_request(R_CHANGE_GROUP,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_group,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    return rsbac_um_remove_gm(ta_number, user, group);
  }

static int sys_rsbac_um_user_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid)
    { 
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_user_exists(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_SEARCH,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      return rsbac_um_user_exists(ta_number, uid);
    }

static int sys_rsbac_um_group_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid)
    { 
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), gid);
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_group_exists(): calling ADF\n");
      }
#endif
    rsbac_target_id.group = gid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_SEARCH,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      return rsbac_um_group_exists(ta_number, gid);
    }

static int sys_rsbac_um_get_next_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t old_user,
  rsbac_uid_t __user * next_user_p)
    {
      rsbac_uid_t k_next_user;
      int err;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(!next_user_p)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(old_user) == RSBAC_UM_VIRTUAL_KEEP)
        old_user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(old_user));
      else
        if (RSBAC_UID_SET(old_user) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      old_user = RSBAC_UID_NUM(old_user);
#endif

      while (!(err = rsbac_um_get_next_user(ta_number, old_user, &k_next_user)))
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_next_user(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = k_next_user;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_SEARCH,
                               task_pid(current),
                               T_USER,
                               rsbac_target_id,
                               A_none,
                               rsbac_attribute_value))
            {
              old_user = k_next_user;
              continue;
            }
        err = rsbac_put_user(&k_next_user, next_user_p, sizeof(k_next_user));
        break;
      }
      return err;
    }

static int sys_rsbac_um_get_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_uid_t __user user_array[],
  u_int       maxnum)
  { 
    long count;
    rsbac_uid_t * k_user_array;
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(maxnum > RSBAC_UM_MAX_MAXNUM)
      maxnum = RSBAC_UM_MAX_MAXNUM;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (vset == RSBAC_UM_VIRTUAL_KEEP)
      vset = rsbac_get_vset();
    else
      if (   (vset > RSBAC_UM_VIRTUAL_MAX)
          && (vset != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    vset = 0;
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_user_list(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = RSBAC_GEN_UID(vset, RSBAC_ALL_USERS);
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_SEARCH,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      /* count only */
      if(!user_array || !maxnum)
        return rsbac_um_get_user_list(ta_number, vset, NULL);

      count = rsbac_um_get_user_list(ta_number, vset, &k_user_array);
      if(count>0)
        {
          if(count > maxnum)
            count = maxnum;
          rsbac_put_user(k_user_array,
                         user_array,
                         count * sizeof(*k_user_array) );
          rsbac_kfree(k_user_array);
        }
      return count;
  } /* end of sys_rsbac_um_get_user_list() */

static int sys_rsbac_um_get_gm_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t __user group_array[],
  u_int       maxnum)
    { 
      long count;
      rsbac_gid_num_t * k_group_array;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(maxnum > RSBAC_UM_MAX_MAXNUM)
        maxnum = RSBAC_UM_MAX_MAXNUM;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(user) == RSBAC_UM_VIRTUAL_KEEP)
        user = RSBAC_GEN_UID (rsbac_get_vset(), user);
      else
        if (RSBAC_UID_SET(user) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      user = RSBAC_UID_NUM(user);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_gm_list(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = user;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_GET_STATUS_DATA,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      /* count only */
      if(!group_array || !maxnum)
        return rsbac_um_get_gm_list(ta_number, user, NULL);

      count = rsbac_um_get_gm_list(ta_number, user, &k_group_array);
      if(count>0)
        {
          if(count > maxnum)
            count = maxnum;
          rsbac_put_user(k_group_array,
                         group_array,
                         count * sizeof(*k_group_array) );
          rsbac_kfree(k_group_array);
        }
      return count;
  } /* end of sys_rsbac_um_get_gm_list() */

static int sys_rsbac_um_get_gm_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group,
  rsbac_uid_num_t __user user_array[],
  u_int       maxnum)
  { 
    long count;
    rsbac_uid_num_t * k_user_array;
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(maxnum > RSBAC_UM_MAX_MAXNUM)
      maxnum = RSBAC_UM_MAX_MAXNUM;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_GID_SET(group) == RSBAC_UM_VIRTUAL_KEEP)
      group = RSBAC_GEN_GID (rsbac_get_vset(), group);
    else
      if (RSBAC_GID_SET(group) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    group = RSBAC_GID_NUM(group);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_gm_user_list(): calling ADF\n");
      }
#endif
    rsbac_target_id.group = group;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_READ,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    /* count number of all users */
    if(!user_array || !maxnum)
      return rsbac_um_get_gm_user_list(ta_number, group, NULL);

    count = rsbac_um_get_gm_user_list(ta_number, group, &k_user_array);
    if(count>0)
      {
        if(count > maxnum)
          count = maxnum;
        rsbac_put_user(k_user_array,
                       user_array,
                       count * sizeof(*k_user_array) );
        rsbac_kfree(k_user_array);
      }
    return count;
    } /* end of sys_rsbac_um_get_gm_user_list() */

static int sys_rsbac_um_get_group_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_gid_t __user group_array[],
  u_int       maxnum)
  { 
    long count;
    rsbac_gid_t * k_group_array;
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if(maxnum > RSBAC_UM_MAX_MAXNUM)
      maxnum = RSBAC_UM_MAX_MAXNUM;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (vset == RSBAC_UM_VIRTUAL_KEEP)
      vset = rsbac_get_vset();
    else
      if (   (vset > RSBAC_UM_VIRTUAL_MAX)
          && (vset != RSBAC_UM_VIRTUAL_ALL)
         )
        return -RSBAC_EINVALIDVALUE;
#else
    vset = 0;
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_group_list(): calling ADF\n");
      }
#endif
    rsbac_target_id.group = RSBAC_GEN_GID(vset, RSBAC_ALL_USERS);
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_SEARCH,
                           task_pid(current),
                           T_GROUP,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      /* count only */
      if(!group_array || !maxnum)
        return rsbac_um_get_group_list(ta_number, vset, NULL);

      count = rsbac_um_get_group_list(ta_number, vset, &k_group_array);
      if(count>0)
        {
          if(count > maxnum)
            count = maxnum;
          rsbac_put_user(k_group_array,
                         group_array,
                         count * sizeof(*k_group_array) );
          rsbac_kfree(k_group_array);
        }
      return count;
    } /* end of sys_rsbac_um_get_group_list() */

static int sys_rsbac_um_get_uid(
  rsbac_list_ta_number_t ta_number,
  char __user * name,
  rsbac_uid_t __user * uid_p)
    { 
      rsbac_uid_t k_uid;
      int err;
      char k_name[RSBAC_MAXNAMELEN];

      if(!name || !uid_p)
        return -RSBAC_EINVALIDPOINTER;

      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        return err;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
      err = rsbac_get_user(&k_uid, uid_p, sizeof(k_uid));
      if(unlikely(err < 0))
        return err;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_uid(): looking up %u/%s\n",
                       RSBAC_UID_SET(k_uid), k_name);
        }
#endif
      /* vset checks are in rsbac_um_get_uid() */
      err = rsbac_um_get_uid(ta_number, k_name, &k_uid);
      if(!err)
        {
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_uid(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = k_uid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_SEARCH,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            err = -EPERM;
          else
            err = rsbac_put_user(&k_uid, uid_p, sizeof(k_uid));
        }
      return err;
    }

static int sys_rsbac_um_get_gid(
  rsbac_list_ta_number_t ta_number,
  char __user * name,
  rsbac_gid_t __user * gid_p)
    { 
      rsbac_gid_t k_gid;
      int err;
      char k_name[RSBAC_MAXNAMELEN];

      if(!name || !gid_p)
        return -RSBAC_EINVALIDPOINTER;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        return err;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
      err = rsbac_get_user(&k_gid, gid_p, sizeof(k_gid));
      if(unlikely(err < 0))
        return err;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_gid(): looking up %u/%s\n",
                       RSBAC_GID_SET(k_gid), k_name);
        }
#endif
      /* vset checks are in rsbac_um_get_gid() */
      err = rsbac_um_get_gid(ta_number, k_name, &k_gid);
      if(!err)
        {
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_gid(): calling ADF\n");
            }
#endif
          rsbac_target_id.group = k_gid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_SEARCH,
                                 task_pid(current),
                                 T_GROUP,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            err = -EPERM;
          else
            err = rsbac_put_user(&k_gid, gid_p, sizeof(k_gid));
        }
      return err;
    }

static int sys_rsbac_um_set_pass_hash(rsbac_uid_t uid,
                          char __user * old_pass,
                          char __user * new_pass,
                          const char __user * hash_algo)
    { 
      int err;
      char __user * k_new_pass;
      char * k_hash_algo;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
      rsbac_um_set_t vset;
#endif

      if(!new_pass)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      vset = rsbac_get_vset();
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (vset, uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

      k_new_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_new_pass)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_new_pass, new_pass, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_new_pass);
          return err;
        }
      k_new_pass[RSBAC_MAXNAMELEN-1] = 0;
      if (hash_algo) {
        k_hash_algo = rsbac_kmalloc_unlocked(RSBAC_UM_ALGO_NAME_LEN);
        if(!k_hash_algo) {
          rsbac_kfree(k_new_pass);
          return -RSBAC_ENOMEM;
        }
        err = strncpy_from_user(k_hash_algo, hash_algo, RSBAC_UM_ALGO_NAME_LEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_hash_algo);
            rsbac_kfree(k_new_pass);
            return err;
          }
        k_hash_algo[RSBAC_UM_ALGO_NAME_LEN-1] = 0;
      } else {
        k_hash_algo = NULL;
      }

      if(   old_pass
         && (RSBAC_UID_NUM(uid) == __kuid_val(current_uid()))
#ifdef CONFIG_RSBAC_UM_VIRTUAL
         && (RSBAC_UID_SET(uid) == vset)
#endif
        )
        {
          char * k_old_pass;

          k_old_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_old_pass)
            {
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_new_pass);
              return -RSBAC_ENOMEM;
            }
          err = strncpy_from_user(k_old_pass, old_pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_old_pass);
              rsbac_kfree(k_new_pass);
              return err;
            }
          k_old_pass[RSBAC_MAXNAMELEN-1] = 0;
          err = rsbac_um_check_pass(uid, k_old_pass);
          rsbac_kfree(k_old_pass);
          if(err)
            {
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_new_pass);
              rsbac_printk(KERN_INFO "sys_rsbac_um_set_pass(): old password check failed\n");
              return err;
            }
          err = rsbac_um_good_pass(uid, k_new_pass);
          if(err)
            {
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_new_pass);
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_um)
                {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                  if(RSBAC_UID_SET(uid))
                    rsbac_printk(KERN_DEBUG
                               "sys_rsbac_um_set_pass(): new password goodness check failed for user %u/%u\n",
                               RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
                  else
#endif
                    rsbac_printk(KERN_DEBUG
                               "sys_rsbac_um_set_pass(): new password goodness check failed for user %u\n",
                               RSBAC_UID_NUM(uid));
                }
#endif
              return err;
            }
        }
      else
        {
          /* check admin rights here */
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
          if(rsbac_freeze)
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_set_pass(): RSBAC configuration frozen, no administration allowed!\n");
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_new_pass);
              return -EPERM;
            }
#endif

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_pass(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = uid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_MODIFY_PERMISSIONS_DATA,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              rsbac_kfree(k_hash_algo);
              rsbac_kfree(k_new_pass);
              return -EPERM;
            }
        }

      err = rsbac_um_set_pass(uid, k_new_pass, k_hash_algo);
      rsbac_kfree(k_hash_algo);
      rsbac_kfree(k_new_pass);
      return err;
    }

static int sys_rsbac_um_set_pass(rsbac_uid_t uid,
                          char __user * old_pass,
                          char __user * new_pass)
    {
      return sys_rsbac_um_set_pass_hash(uid, old_pass, new_pass, NULL); 
    }

static int sys_rsbac_um_set_pass_name_hash(char __user * name,
                               char __user * old_pass,
                               char __user * new_pass,
                               const char __user * hash_algo)
    {
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char * k_name;

      if(!name || !new_pass)
        return -RSBAC_EINVALIDPOINTER;
      k_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_name)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_name);
          return err;
        }
      k_name[RSBAC_MAXNAMELEN-1] = 0;

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_pass_name(): user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      rsbac_kfree(k_name);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_pass_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
        }
      else
        err = sys_rsbac_um_set_pass_hash(uid, old_pass, new_pass, hash_algo);

      return err;
    }

static int sys_rsbac_um_set_pass_name(char __user * name,
                               char __user * old_pass,
                               char __user * new_pass)
    {
      return sys_rsbac_um_set_pass_name_hash(name, old_pass, new_pass, NULL);
    }

static int sys_rsbac_um_add_onetime_hash(rsbac_uid_t uid,
                          char __user * old_pass,
                          char __user * new_pass,
                          char __user * hash_algo,
                          rsbac_time_t ttl)
    { 
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
      char * k_new_pass;
      char * k_hash_algo = NULL;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
      rsbac_um_set_t vset;
#endif

      if(!new_pass)
        return -RSBAC_EINVALIDPOINTER;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      vset = rsbac_get_vset();
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (vset, uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

      k_new_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_new_pass)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_new_pass, new_pass, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_new_pass);
          return err;
        }
      k_new_pass[RSBAC_MAXNAMELEN-1] = 0;

      if(   old_pass
         && (RSBAC_UID_NUM(uid) == __kuid_val(current_uid()))
#ifdef CONFIG_RSBAC_UM_VIRTUAL
         && (RSBAC_UID_SET(uid) == vset)
#endif
        )
        {
          char * k_old_pass;

          k_old_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_old_pass)
            {
              rsbac_kfree(k_new_pass);
              return -RSBAC_ENOMEM;
            }
          err = strncpy_from_user(k_old_pass, old_pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_old_pass);
              rsbac_kfree(k_new_pass);
              return err;
            }
          k_old_pass[RSBAC_MAXNAMELEN-1] = 0;
          err = rsbac_um_check_pass(uid, k_old_pass);
          rsbac_kfree(k_old_pass);
          if(err)
            {
              rsbac_kfree(k_new_pass);
              rsbac_printk(KERN_INFO "sys_rsbac_um_add_onetime(): old password check failed\n");
              return err;
            }
          err = rsbac_um_good_pass(uid, k_new_pass);
          if(err)
            {
              rsbac_kfree(k_new_pass);
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_um)
                {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                  if(RSBAC_UID_SET(uid))
                    rsbac_printk(KERN_DEBUG
                               "sys_rsbac_um_add_onetime(): new password goodness check failed for user %u/%u\n",
                               RSBAC_UID_SET(uid), RSBAC_UID_NUM(uid));
                  else
#endif
                    rsbac_printk(KERN_DEBUG
                               "sys_rsbac_um_add_onetime(): new password goodness check failed for user %u\n",
                               RSBAC_UID_NUM(uid));
                }
#endif
              return err;
            }
        }
      else
        {
          /* check admin rights here */
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
          if(rsbac_freeze)
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_add_onetime(): RSBAC configuration frozen, no administration allowed!\n");
              rsbac_kfree(k_new_pass);
              return -EPERM;
            }
#endif

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_onetime(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = uid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_MODIFY_PERMISSIONS_DATA,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              rsbac_kfree(k_new_pass);
              return -EPERM;
            }
        }

      if (hash_algo)
        {
          k_hash_algo = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_hash_algo)
            {
              rsbac_kfree(k_new_pass);
              return -RSBAC_ENOMEM;
            }
          err = strncpy_from_user(k_hash_algo, hash_algo, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_new_pass);
              rsbac_kfree(k_hash_algo);
              return err;
            }
          k_hash_algo[RSBAC_MAXNAMELEN-1] = 0;
        }

      err = rsbac_um_add_onetime(uid, k_new_pass, k_hash_algo, ttl);
      rsbac_kfree(k_new_pass);
      rsbac_kfree(k_hash_algo);
      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_add_onetime(rsbac_uid_t uid,
                          char __user * old_pass,
                          char __user * new_pass,
                          rsbac_time_t ttl)
    {
      return sys_rsbac_um_add_onetime_hash(uid, old_pass, new_pass, NULL, ttl); 
    }

static int sys_rsbac_um_add_onetime_name_hash(char __user * name,
                               char __user * old_pass,
                               char __user * new_pass,
                               char __user * hash_algo,
                               rsbac_time_t ttl)
    {
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char * k_name;

      if(!name || !new_pass)
        return -RSBAC_EINVALIDPOINTER;
      k_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_name)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_name);
          return err;
        }
      k_name[RSBAC_MAXNAMELEN-1] = 0;

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_onetime_name(): user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      rsbac_kfree(k_name);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_add_onetime_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
        }
      else
        err = sys_rsbac_um_add_onetime_hash(uid, old_pass, new_pass, hash_algo, ttl);

      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_add_onetime_name(char __user * name,
                               char __user * old_pass,
                               char __user * new_pass,
                               rsbac_time_t ttl)
    {
      return sys_rsbac_um_add_onetime_name_hash(name, old_pass, new_pass, NULL, ttl);
    }

static int sys_rsbac_um_remove_all_onetime(rsbac_uid_t uid,
                          char __user * old_pass)
    { 
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
      rsbac_um_set_t vset;
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      vset = rsbac_get_vset();
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (vset, uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

      if(   old_pass
         && (RSBAC_UID_NUM(uid) == __kuid_val(current_uid()))
#ifdef CONFIG_RSBAC_UM_VIRTUAL
         && (RSBAC_UID_SET(uid) == vset)
#endif
        )
        {
          char * k_old_pass;

          k_old_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_old_pass)
            {
              return -RSBAC_ENOMEM;
            }
          err = strncpy_from_user(k_old_pass, old_pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_old_pass);
              return err;
            }
          k_old_pass[RSBAC_MAXNAMELEN-1] = 0;
          err = rsbac_um_check_pass(uid, k_old_pass);
          rsbac_kfree(k_old_pass);
          if(err)
            {
              rsbac_printk(KERN_INFO "sys_rsbac_um_remove_all_onetime(): old password check failed\n");
              return err;
            }
        }
      else
        {
          /* check admin rights here */
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
          if(rsbac_freeze)
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_remove_all_onetime(): RSBAC configuration frozen, no administration allowed!\n");
              return -EPERM;
            }
#endif

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_all_onetime(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = uid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_MODIFY_PERMISSIONS_DATA,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              return -EPERM;
            }
        }

      err = rsbac_um_remove_all_onetime(uid);
      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_remove_all_onetime_name(char __user * name,
                               char __user * old_pass)
    {
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char * k_name;

      if(!name)
        return -RSBAC_EINVALIDPOINTER;
      k_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_name)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_name);
          return err;
        }
      k_name[RSBAC_MAXNAMELEN-1] = 0;

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_all_onetime_name(): user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      rsbac_kfree(k_name);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_remove_all_onetime_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
        }
      else
        err = sys_rsbac_um_remove_all_onetime(uid, old_pass);

      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_count_onetime(rsbac_uid_t uid,
                          char __user * old_pass)
    { 
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
      rsbac_um_set_t vset;
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      vset = rsbac_get_vset();
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (vset, uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

      if(   old_pass
         && (RSBAC_UID_NUM(uid) == __kuid_val(current_uid()))
#ifdef CONFIG_RSBAC_UM_VIRTUAL
         && (RSBAC_UID_SET(uid) == vset)
#endif
        )
        {
          char * k_old_pass;

          k_old_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_old_pass)
            {
              return -RSBAC_ENOMEM;
            }
          err = strncpy_from_user(k_old_pass, old_pass, RSBAC_MAXNAMELEN);
          if(unlikely(err < 0))
            {
              rsbac_kfree(k_old_pass);
              return err;
            }
          k_old_pass[RSBAC_MAXNAMELEN-1] = 0;
          err = rsbac_um_check_pass(uid, k_old_pass);
          rsbac_kfree(k_old_pass);
          if(err)
            {
              rsbac_printk(KERN_INFO "sys_rsbac_um_count_onetime(): old password check failed\n");
              return err;
            }
        }
      else
        {
          /* check admin rights here */
          union rsbac_target_id_t       rsbac_target_id;
          union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
          if(rsbac_freeze)
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_count_onetime(): RSBAC configuration frozen, no administration allowed!\n");
              return -EPERM;
            }
#endif

#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_count_onetime(): calling ADF\n");
            }
#endif
          rsbac_target_id.user = uid;
          rsbac_attribute_value.dummy = 0;
          if (!rsbac_adf_request(R_READ,
                                 task_pid(current),
                                 T_USER,
                                 rsbac_target_id,
                                 A_none,
                                 rsbac_attribute_value))
            {
              return -EPERM;
            }
        }

      return rsbac_um_count_onetime(uid);
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_count_onetime_name(char __user * name,
                               char __user * old_pass)
    {
#if defined(CONFIG_RSBAC_UM_ONETIME)
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char * k_name;

      if(!name)
        return -RSBAC_EINVALIDPOINTER;
      k_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
      if(!k_name)
        return -RSBAC_ENOMEM;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        {
          rsbac_kfree(k_name);
          return err;
        }
      k_name[RSBAC_MAXNAMELEN-1] = 0;

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_count_onetime_name(): user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      rsbac_kfree(k_name);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_count_onetime_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
        }
      else
        err = sys_rsbac_um_count_onetime(uid, old_pass);

      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }

static int sys_rsbac_um_set_group_pass_hash(rsbac_gid_t gid,
                                char __user * new_pass,
                                const char __user * hash_algo)
    { 
      int err;
      char * k_new_pass;
      char * k_hash_algo;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_FREEZE_UM
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_um_set_group_pass(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_GID_SET(gid) == RSBAC_UM_VIRTUAL_KEEP)
        gid = RSBAC_GEN_GID (rsbac_get_vset(), RSBAC_GID_NUM(gid));
      else
        if (RSBAC_GID_SET(gid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      gid = RSBAC_GID_NUM(gid);
#endif

      /* check admin rights here */
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_group_pass(): calling ADF\n");
        }
#endif
      rsbac_target_id.group = gid;
      rsbac_attribute_value.dummy = 0;
      if (!rsbac_adf_request(R_MODIFY_PERMISSIONS_DATA,
                             task_pid(current),
                             T_GROUP,
                             rsbac_target_id,
                             A_none,
                             rsbac_attribute_value))
        {
          return -EPERM;
        }

      if (hash_algo) {
        k_hash_algo = rsbac_kmalloc_unlocked(RSBAC_UM_ALGO_NAME_LEN);
        if(!k_hash_algo) {
           return -RSBAC_ENOMEM;
        }
        err = strncpy_from_user(k_hash_algo, hash_algo, RSBAC_UM_ALGO_NAME_LEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_hash_algo);
            return -RSBAC_EINVALIDVALUE;
          }
        k_hash_algo[RSBAC_UM_ALGO_NAME_LEN-1] = 0;
      } else {
        k_hash_algo = NULL;
      }

      if(new_pass)
        {
          k_new_pass = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
          if(!k_new_pass) {
            rsbac_kfree(k_hash_algo);
            return -RSBAC_ENOMEM;
          }
          err = strncpy_from_user(k_new_pass, new_pass, RSBAC_MAXNAMELEN);
          if(likely(err >= 0))
            {
              k_new_pass[RSBAC_MAXNAMELEN-1] = 0;
              err = rsbac_um_set_group_pass(gid, k_new_pass, k_hash_algo);
            }
          rsbac_kfree(k_new_pass);
        }
      else
        {
          err = rsbac_um_set_group_pass(gid, NULL, k_hash_algo);
        }
      rsbac_kfree(k_hash_algo);
      return err;
    }

static int sys_rsbac_um_set_group_pass(rsbac_gid_t gid,
                                char __user * new_pass)
    {
      return sys_rsbac_um_set_group_pass_hash(gid, new_pass, NULL); 
    }

static int sys_rsbac_um_check_account(rsbac_uid_t uid)
    { 
      int err;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_check_account(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_GET_STATUS_DATA,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      err = rsbac_um_check_account(uid);
      if(err == -RSBAC_ENOTFOUND)
        err = -EPERM;
      return err;
    }

static int sys_rsbac_um_check_account_name(char __user * name)
    { 
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char k_name[RSBAC_MAXNAMELEN];
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(!name)
        return -RSBAC_EINVALIDPOINTER;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        return err;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_check_account_name(): checking user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_check_account_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
          if(err == -RSBAC_ENOTFOUND)
            err = -EPERM;
          return err;
        }

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_check_account_name(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_GET_STATUS_DATA,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      err = rsbac_um_check_account(uid);
      if(err == -RSBAC_ENOTFOUND)
        err = -EPERM;
      return err;
    }

static int sys_rsbac_um_get_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid)
    {
#ifdef CONFIG_RSBAC_UM_PWHISTORY
      int err;
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_max_history(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_READ,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      err = rsbac_um_get_max_history(ta_number, uid);
      if(err == -RSBAC_ENOTFOUND)
        err = -EPERM;
      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif
    }

static int sys_rsbac_um_get_max_history_name(rsbac_list_ta_number_t ta_number, char __user * name)
    {
#ifdef CONFIG_RSBAC_UM_PWHISTORY
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char k_name[RSBAC_MAXNAMELEN];
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(!name)
        return -RSBAC_EINVALIDPOINTER;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        return err;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_max_history_name(): getting max_history of user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_max_history_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
          if(err == -RSBAC_ENOTFOUND)
            err = -EPERM;
          return err;
        }

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_get_max_history_name(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_READ,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

      err = rsbac_um_get_max_history(ta_number, uid);
      if(err == -RSBAC_ENOTFOUND)
        err = -EPERM;
      return err;
#else
    return -RSBAC_EINVALIDMODULE;
#endif
    }

static int sys_rsbac_um_set_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid, __u8 max_history)
    {
#ifdef CONFIG_RSBAC_UM_PWHISTORY
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
      if (RSBAC_UID_SET(uid) == RSBAC_UM_VIRTUAL_KEEP)
        uid = RSBAC_GEN_UID (rsbac_get_vset(), uid);
      else
        if (RSBAC_UID_SET(uid) > RSBAC_UM_VIRTUAL_MAX)
          return -RSBAC_EINVALIDVALUE;
#else
      uid = RSBAC_UID_NUM(uid);
#endif

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_max_history(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_WRITE,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    return rsbac_um_set_max_history(ta_number, uid, max_history);
#else
    return -RSBAC_EINVALIDMODULE;
#endif
    }

static int sys_rsbac_um_set_max_history_name(rsbac_list_ta_number_t ta_number, char __user * name, __u8 max_history)
    {
#ifdef CONFIG_RSBAC_UM_PWHISTORY
      int err;
      rsbac_uid_t uid = RSBAC_GEN_UID(RSBAC_UM_VIRTUAL_KEEP, RSBAC_NO_USER);
      char k_name[RSBAC_MAXNAMELEN];
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if(!name)
        return -RSBAC_EINVALIDPOINTER;
      err = strncpy_from_user(k_name, name, RSBAC_MAXNAMELEN);
      if(unlikely(err < 0))
        return err;
      k_name[RSBAC_MAXNAMELEN-1] = 0;
#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef_um)
        {
          rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_max_history_name(): setting max_history of user %s\n",
                       k_name);
      }
#endif
      err = rsbac_um_get_uid(0, k_name, &uid);
      if(err)
        {
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_um)
            {
              rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_max_history_name(): lookup of user %s failed\n",
                           k_name);
            }
#endif
          if(err == -RSBAC_ENOTFOUND)
            err = -EPERM;
          return err;
        }

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_set_max_history_name(): calling ADF\n");
      }
#endif
    rsbac_target_id.user = uid;
    rsbac_attribute_value.dummy = 0;
    if (!rsbac_adf_request(R_WRITE,
                           task_pid(current),
                           T_USER,
                           rsbac_target_id,
                           A_none,
                           rsbac_attribute_value))
      {
        return -EPERM;
      }

    return rsbac_um_set_max_history(ta_number, uid, max_history);
#else
    return -RSBAC_EINVALIDMODULE;
#endif
    }

static int sys_rsbac_um_select_vset(rsbac_um_set_t vset)
    { 
#if defined(CONFIG_RSBAC_UM_VIRTUAL)
      union rsbac_target_id_t       rsbac_target_id;
      union rsbac_target_id_t       rsbac_new_target_id;
      union rsbac_attribute_value_t rsbac_attribute_value;

      if (vset > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;

#ifdef CONFIG_RSBAC_DEBUG
      if (rsbac_debug_aef)
        rsbac_printk(KERN_DEBUG "sys_rsbac_um_select_vset(): calling ADF\n");
#endif
      rsbac_target_id.process = task_pid(current);
      rsbac_attribute_value.owner = RSBAC_GEN_UID(vset, __kuid_val(current_uid()));
      if (!rsbac_adf_request(R_CHANGE_OWNER,
                             task_pid(current),
                             T_PROCESS,
                             rsbac_target_id,
                             A_owner,
                             rsbac_attribute_value))
        {
          return -EPERM;
        }

      rsbac_pr_debug(aef_um, "Switching process %u to vset %u\n",
                     current->pid, vset);
      rsbac_target_id.process = task_pid(current);
      rsbac_attribute_value.vset = vset;
      if (rsbac_set_attr(SW_GEN,
                         T_PROCESS,
                         rsbac_target_id,
                         A_vset,
                         rsbac_attribute_value))
        {
          rsbac_ds_set_error("sys_rsbac_um_select_vset()", A_vset);
        }
      else
        {
          rsbac_target_id.process = task_pid(current);
          rsbac_attribute_value.owner = RSBAC_GEN_UID(vset, __kuid_val(current_uid()));
          rsbac_new_target_id.dummy = 0;
          if (rsbac_adf_set_attr(R_CHANGE_OWNER,
                                 task_pid(current),
                                 T_PROCESS,
                                 rsbac_target_id,
                                 T_NONE,
                                 rsbac_new_target_id,
                                 A_owner,
                                 rsbac_attribute_value))
            {
              rsbac_printk(KERN_WARNING
                           "sys_rsbac_um_select_vset(): rsbac_adf_set_attr() returned error\n");
            }
        }
      return 0;
#else
    return -RSBAC_EINVALIDMODULE;
#endif    
    }
#endif

/************** UDF ***************/

#ifdef CONFIG_RSBAC_UDF
static int sys_rsbac_udf_flush_cache(void)
  {
#ifndef CONFIG_RSBAC_UDF_CACHE
    return 0;
#else
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    /* Security Officer or admin? */
    i_tid.user = __kuid_val(current_uid());
    if (rsbac_get_attr(SW_UDF,
                       T_USER,
                       i_tid,
                       A_udf_role,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING
                     "sys_rsbac_udf_flush_cache(): rsbac_get_attr() returned error!\n");
        return -EPERM;
      }
    /* if not sec_officer or admin, deny */
    if (   (i_attr_val1.system_role != SR_security_officer)
        && (i_attr_val1.system_role != SR_administrator)
       )
      #ifdef CONFIG_RSBAC_SOFTMODE
      if(   !rsbac_softmode
      #ifdef CONFIG_RSBAC_SOFTMODE_IND
         && !rsbac_ind_softmode[SW_UDF]
      #endif
        )
      #endif
      return -EPERM;

    rsbac_printk(KERN_INFO
           "sys_rsbac_udf_flush_cache(): flushing UDF result cache!\n");

    return rsbac_udf_flush_cache();
#endif
  }
#endif


/************************************************* */
/*             DEBUG/LOG functions                 */
/************************************************* */

static int sys_rsbac_adf_log_switch(enum rsbac_adf_request_t request,
                             enum rsbac_target_t      target,
                             u_int                    value)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;

    if ((value != LL_none) && (value != LL_denied) && (value != LL_full))
      return -RSBAC_EINVALIDVALUE;
    if(request >= R_NONE)
      return -RSBAC_EINVALIDREQUEST;
    if(   (target == T_FD)
       || (target > T_NONE)
      )
      return -RSBAC_EINVALIDTARGET;

#ifdef CONFIG_RSBAC_FREEZE
      if(rsbac_freeze)
        {
          rsbac_printk(KERN_WARNING
                       "sys_rsbac_adf_log_switch(): RSBAC configuration frozen, no administration allowed!\n");
          return -EPERM;
        }
#endif

    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "sys_rsbac_adf_log_switch(): calling ADF\n");
#endif
    rsbac_target_id.dummy = 0;
    rsbac_attribute_value.request = request;
    if (!rsbac_adf_request(R_SWITCH_LOG,
                           task_pid(current),
                           T_NONE,
                           rsbac_target_id,
                           A_request,
                           rsbac_attribute_value))
             {
               return -EPERM;
             }
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        char * request_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
        if(request_name)
          {
            get_request_name(request_name, request);
            rsbac_printk(KERN_INFO "sys_rsbac_adf_log_switch(): switching RSBAC module logging for request %s (No. %i) to %i!\n",
                   request_name, target, value);
            rsbac_kfree(request_name);
          }
      }
#endif
    rsbac_adf_log_switch(request,target,value);
    return 0;
  }

static int sys_rsbac_get_adf_log(enum rsbac_adf_request_t   request,
                          enum rsbac_target_t        target,
                          u_int             __user * value_p)
  {
    union rsbac_target_id_t       rsbac_target_id;
    union rsbac_attribute_value_t rsbac_attribute_value;
    u_int k_value;
    int err;

    if(request >= R_NONE)
      return -RSBAC_EINVALIDREQUEST;
    if(   (target == T_FD)
       || (target > T_NONE)
      )
      return -RSBAC_EINVALIDTARGET;
    if(!value_p)
      return -RSBAC_EINVALIDPOINTER;
    /* call ADF */
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      rsbac_printk(KERN_DEBUG "sys_rsbac_get_adf_log(): calling ADF\n");
#endif
    rsbac_target_id.scd = ST_rsbac;
    rsbac_attribute_value.request = request;
    if (!rsbac_adf_request(R_GET_STATUS_DATA,
                           task_pid(current),
                           T_SCD,
                           rsbac_target_id,
                           A_request,
                           rsbac_attribute_value))
             {
               return -EPERM;
             }
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        char * request_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
        if(request_name)
          {
            get_request_name(request_name, request);
            rsbac_printk(KERN_DEBUG "sys_rsbac_get_adf_log(): getting RSBAC module logging for request %s (No. %i)!\n",
                   request_name, target);
            rsbac_kfree(request_name);
          }
      }
#endif
    err = rsbac_get_adf_log(request, target, &k_value);
    if(!err)
      {
        rsbac_put_user(&k_value,
                       value_p,
                       sizeof(k_value) );
      }
    return err;
  }

/*
 * Commands to sys_rsbac_log:
 *
 * 	0 -- Close the log.  Currently a NOP.
 * 	1 -- Open the log. Currently a NOP.
 * 	2 -- Read from the log.
 * 	3 -- Read up to the last 4k of messages in the ring buffer.
 * 	4 -- Read and clear last 4k of messages in the ring buffer
 * 	5 -- Clear ring buffer.
 */
static int sys_rsbac_log(int type,
                  char __user * buf,
                  int len)
  {
#if defined(CONFIG_RSBAC_RMSG)
    return rsbac_log(type,buf,len);
#else
    return 0;
#endif /* RMSG */
  }

#if defined(CONFIG_RSBAC_INIT_DELAY)
static int sys_rsbac_init(char __user * path)
  {
    struct dentry * t_dentry = NULL;
    rsbac_boolean_t need_put = FALSE;
    int     err = 0;

    struct path ppath;

    if(!path)
      return rsbac_init(ROOT_DEV);

    if ((err = user_path_at(AT_FDCWD, path, 0, &ppath)))
      {
        goto out;
      }
      t_dentry = ppath.dentry;
    need_put = TRUE;
    if (!t_dentry->d_inode)
      {
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    /* is inode of type file, symlink or block/char device? */
    if(!S_ISBLK(t_dentry->d_inode->i_mode))
      { /* This is no file or device */
        err = -RSBAC_EINVALIDTARGET;
        goto out_dput;
      }
    err = rsbac_init(t_dentry->d_sb->s_dev);

out_dput:
      if(need_put)
        path_put(&ppath);
out:
      return err;
  }
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
static int sys_rsbac_list_ta_begin_name(
  rsbac_time_t ttl,
  rsbac_list_ta_number_t __user * ta_number_p,
  rsbac_uid_t commit_uid,
  char __user * name,
  char __user * password)
  {
    int err;
    rsbac_list_ta_number_t k_ta_number = 0;
    char * k_name = NULL;
    char * k_password = NULL;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if (RSBAC_UID_SET(commit_uid) == RSBAC_UM_VIRTUAL_KEEP)
      commit_uid = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(commit_uid));
    else
      if (RSBAC_UID_SET(commit_uid) > RSBAC_UM_VIRTUAL_MAX)
        return -RSBAC_EINVALIDVALUE;
#else
    commit_uid = RSBAC_UID_NUM(commit_uid);
#endif
    if(name)
      {
        k_name = rsbac_kmalloc_unlocked(RSBAC_LIST_TA_MAX_NAMELEN);
        if(!k_name)
          return -ENOMEM;
        err = strncpy_from_user(k_name, name, RSBAC_LIST_TA_MAX_NAMELEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_name);
            return err;
          }
        k_name[RSBAC_LIST_TA_MAX_NAMELEN - 1] = 0;
      }
    if(password)
      {
        k_password = rsbac_kmalloc_unlocked(RSBAC_LIST_TA_MAX_PASSLEN);
        if(!k_password)
          return -ENOMEM;
        err = strncpy_from_user(k_password, password, RSBAC_LIST_TA_MAX_PASSLEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_password);
            return err;
          }
        k_password[RSBAC_LIST_TA_MAX_PASSLEN - 1] = 0;
      }
    err = rsbac_list_ta_begin(ttl, &k_ta_number, commit_uid, k_name, k_password);
    if(!err)
      err = rsbac_put_user(&k_ta_number,
                           ta_number_p,
                           sizeof(k_ta_number) );
    if(k_name)
      rsbac_kfree(k_name);
    if(k_password)
      rsbac_kfree(k_password);
    return err;
  }

static int sys_rsbac_list_ta_begin(
  rsbac_time_t ttl,
  rsbac_list_ta_number_t __user * ta_number_p,
  rsbac_uid_t commit_uid,
  char __user * password)
  {
    return sys_rsbac_list_ta_begin_name(ttl, ta_number_p, commit_uid, NULL, password);
  }

static int sys_rsbac_list_ta_refresh(
  rsbac_time_t ttl,
  rsbac_list_ta_number_t ta_number,
  char __user * password)
  {
    int err;
    char * k_password;

    if(password)
      {
        k_password = rsbac_kmalloc_unlocked(RSBAC_LIST_TA_MAX_PASSLEN);
        if(!k_password)
          return -ENOMEM;
        err = strncpy_from_user(k_password, password, RSBAC_LIST_TA_MAX_PASSLEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_password);
            return err;
          }
        k_password[RSBAC_LIST_TA_MAX_PASSLEN - 1] = 0;
      }
    else
      k_password = NULL;
    err = rsbac_list_ta_refresh(ttl, ta_number, k_password);
    if(k_password)
      rsbac_kfree(k_password);
    return err;
  }

static int sys_rsbac_list_ta_commit(
  rsbac_list_ta_number_t ta_number,
  char __user * password)
  {
    int err;
    char * k_password;

    if(password)
      {
        k_password = rsbac_kmalloc_unlocked(RSBAC_LIST_TA_MAX_PASSLEN);
        if(!k_password)
          return -ENOMEM;
        err = strncpy_from_user(k_password, password, RSBAC_LIST_TA_MAX_PASSLEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_password);
            return err;
          }
        k_password[RSBAC_LIST_TA_MAX_PASSLEN - 1] = 0;
      }
    else
      k_password = NULL;
    err = rsbac_list_ta_commit(ta_number, k_password);
    if(k_password)
      rsbac_kfree(k_password);
    return err;
  }

static int sys_rsbac_list_ta_forget(
  rsbac_list_ta_number_t ta_number,
  char __user * password)
  {
    int err;
    char * k_password;

    if(password)
      {
        k_password = rsbac_kmalloc_unlocked(RSBAC_LIST_TA_MAX_PASSLEN);
        if(!k_password)
          return -ENOMEM;
        err = strncpy_from_user(k_password, password, RSBAC_LIST_TA_MAX_PASSLEN);
        if(unlikely(err < 0))
          {
            rsbac_kfree(k_password);
            return err;
          }
        k_password[RSBAC_LIST_TA_MAX_PASSLEN - 1] = 0;
      }
    else
      k_password = NULL;
    err = rsbac_list_ta_forget(ta_number, k_password);
    if(k_password)
      rsbac_kfree(k_password);
    return err;
  }
#endif

/* Big dispatcher for all syscalls */
SYSCALL_DEFINE3(rsbac, rsbac_version_t, version, enum rsbac_syscall_t, call, union rsbac_syscall_arg_t __user *, arg_p)
  {
    int err;

    if( (!rsbac_initialized) && (call != RSYS_init) ) {
	    rsbac_printk(KERN_WARNING "sys_rsbac(): RSBAC not initialized\n");
	    return -RSBAC_ENOTINITIALIZED;
    }

    if (   (   (version < RSBAC_API_MIN_VERSION_NR)
            || (version > RSBAC_API_MAX_VERSION_NR)
           )
        && (call != RSYS_version)
        && (call != RSYS_api_min_version)
        && (call != RSYS_api_max_version)
       )
      return -RSBAC_EINVALIDVERSION;

    if(call >= RSYS_none)
      return -RSBAC_EINVALIDREQUEST;

#ifdef CONFIG_RSBAC_XSTATS
    syscall_count[call]++;
#endif

#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
    if((current->thread_info.status & TS_COMPAT) || test_thread_flag(TIF_ADDR32)) {
      union rsbac_syscall_arg_ia32_t k_arg;

      /* get values from user space */
      if(arg_p)
        {
          err = rsbac_get_user(&k_arg, arg_p, sizeof(k_arg) );
          if(unlikely(err < 0))
            return err;
        }
      else
        {
          memset(&k_arg, 0, sizeof(k_arg));
        }

      switch(call)
        {
#ifdef CONFIG_RSBAC_UM
          case RSYS_um_get_user_item:
            return sys_rsbac_um_get_user_item(k_arg.um_get_user_item.ta_number,
                                              k_arg.um_get_user_item.uid,
                                              k_arg.um_get_user_item.mod,
                                              (void __user *)(long)k_arg.um_get_user_item.data_p);
          case RSYS_um_get_uid:
            return sys_rsbac_um_get_uid(k_arg.um_get_uid.ta_number,
                                        (void __user *)(long)k_arg.um_get_uid.name,
                                        (void __user *)(long)k_arg.um_get_uid.uid_p);
          case RSYS_um_get_group_item:
            return sys_rsbac_um_get_group_item(k_arg.um_get_group_item.ta_number,
                                               k_arg.um_get_group_item.gid,
                                               k_arg.um_get_group_item.mod,
                                               (void __user *)(long)k_arg.um_get_group_item.data_p);
          case RSYS_um_get_gm_list:
            return sys_rsbac_um_get_gm_list(k_arg.um_get_gm_list.ta_number,
                                            k_arg.um_get_gm_list.user,
                                            (void __user *)(long)k_arg.um_get_gm_list.group_array,
                                            k_arg.um_get_gm_list.maxnum);
          case RSYS_um_get_gm_user_list:
            return sys_rsbac_um_get_gm_user_list(k_arg.um_get_gm_user_list.ta_number,
                                                 k_arg.um_get_gm_user_list.group,
                                                 (void __user *)(long)k_arg.um_get_gm_user_list.user_array,
                                                 k_arg.um_get_gm_user_list.maxnum);
          case RSYS_um_get_gid:
            return sys_rsbac_um_get_gid(k_arg.um_get_gid.ta_number,
                                        (void __user *)(long)k_arg.um_get_gid.name,
                                        (void __user *)(long)k_arg.um_get_gid.gid_p);
          case RSYS_um_get_user_list:
            return sys_rsbac_um_get_user_list(k_arg.um_get_user_list.ta_number,
                                              k_arg.um_get_user_list.vset,
                                              (void __user *)(long)k_arg.um_get_user_list.user_array,
                                              k_arg.um_get_user_list.maxnum);
          case RSYS_um_check_account_name:
            return sys_rsbac_um_check_account_name((void __user *)(long)k_arg.um_check_account_name.name);
#endif
          case RSYS_get_attr:
            return sys_rsbac_get_attr(k_arg.get_attr.ta_number,
                                      k_arg.get_attr.module,
                                      k_arg.get_attr.target,
                                      (void __user *)(long)k_arg.get_attr.tid,
                                      k_arg.get_attr.attr,
                                      (void __user *)(long)k_arg.get_attr.value,
                                      k_arg.get_attr.inherit);
          case RSYS_get_attr_n:
            return sys_rsbac_get_attr_n(k_arg.get_attr_n.ta_number,
                                        k_arg.get_attr_n.module,
                                        k_arg.get_attr_n.target,
                                        (void __user *)(long)k_arg.get_attr_n.t_name,
                                        k_arg.get_attr_n.attr,
                                        (void __user *)(long)k_arg.get_attr_n.value,
                                        k_arg.get_attr_n.inherit);
          case RSYS_set_attr:
            return sys_rsbac_set_attr(k_arg.set_attr.ta_number,
                                      k_arg.set_attr.module,
                                      k_arg.set_attr.target,
                                      (void __user *)(long)k_arg.set_attr.tid,
                                      k_arg.set_attr.attr,
                                      (void __user *)(long)k_arg.set_attr.value);
          case RSYS_set_attr_n:
            return sys_rsbac_set_attr_n(k_arg.set_attr_n.ta_number,
                                        k_arg.set_attr_n.module,
                                        k_arg.set_attr_n.target,
                                        (void __user *)(long)k_arg.set_attr_n.t_name,
                                        k_arg.set_attr_n.attr,
                                        (void __user *)(long)k_arg.set_attr_n.value);
#ifdef CONFIG_RSBAC_RC
          case RSYS_rc_get_current_role:
            return sys_rsbac_rc_get_current_role((void __user *)(long)k_arg.rc_get_current_role.role_p);
          case RSYS_rc_get_item:
            return sys_rsbac_rc_get_item(k_arg.rc_get_item.ta_number,
                                         k_arg.rc_get_item.target,
                                         (void __user *)(long)k_arg.rc_get_item.tid_p,
                                         (void __user *)(long)k_arg.rc_get_item.subtid_p,
                                         k_arg.rc_get_item.item,
                                         (void __user *)(long)k_arg.rc_get_item.value_p,
                                         (void __user *)(long)k_arg.rc_get_item.ttl_p);
          case RSYS_rc_change_role:
            return sys_rsbac_rc_change_role(k_arg.rc_change_role.role,
                                            (void __user *)(long)k_arg.rc_change_role.pass);
#endif
#ifdef CONFIG_RSBAC_JAIL
          case RSYS_jail:
            return rsbac_jail_sys_jail(k_arg.jail.version,
                                       (void __user *)(long)k_arg.jail.path,
                                       k_arg.jail.ip,
                                       k_arg.jail.flags,
                                       k_arg.jail.max_caps,
                                       k_arg.jail.scd_get,
                                       k_arg.jail.scd_modify);
#endif

          case RSYS_remove_target:
            return sys_rsbac_remove_target(k_arg.remove_target.ta_number,
                                           k_arg.remove_target.target,
                                           (void __user *)(long)k_arg.remove_target.tid);
          case RSYS_remove_target_n:
            return sys_rsbac_remove_target_n(k_arg.remove_target_n.ta_number,
                                             k_arg.remove_target_n.target,
                                             (void __user *)(long)k_arg.remove_target_n.t_name);
          case RSYS_net_list_all_netdev:
            return sys_rsbac_net_list_all_netdev(k_arg.net_list_all_netdev.ta_number,
                                                 (void __user *)(long)k_arg.net_list_all_netdev.id_p,
                                                 k_arg.net_list_all_netdev.maxnum);
          case RSYS_net_template:
            return sys_rsbac_net_template(k_arg.net_template.ta_number,
                                          k_arg.net_template.call,
                                          k_arg.net_template.id,
                                          (void __user *)(long)k_arg.net_template.data_p);
          case RSYS_net_list_all_template:
            return sys_rsbac_net_list_all_template(k_arg.net_list_all_template.ta_number,
                                                   (void __user *)(long)k_arg.net_list_all_template.id_p,
                                                   k_arg.net_list_all_template.maxnum);
          case RSYS_switch:
            return sys_rsbac_switch(k_arg.switch_module.module,
                                    k_arg.switch_module.value);
	case RSYS_get_switch:
	  return sys_rsbac_get_switch(k_arg.get_switch_module.module,
					(void __user *)(long)k_arg.get_switch_module.value_p,
					(void __user *)(long)k_arg.get_switch_module.switchable_p);
          case RSYS_adf_log_switch:
            return sys_rsbac_adf_log_switch(k_arg.adf_log_switch.request,
                                            k_arg.adf_log_switch.target,
                                            k_arg.adf_log_switch.value);
          case RSYS_get_adf_log:
            return sys_rsbac_get_adf_log(k_arg.get_adf_log.request,
                                         k_arg.get_adf_log.target,
                                         (void __user *)(long)k_arg.get_adf_log.value_p);
          case RSYS_write:
            return sys_rsbac_write();
          case RSYS_log:
            return sys_rsbac_log(k_arg.log.type,
                                 (void __user *)(long)k_arg.log.buf,
                                 k_arg.log.len);
#ifdef CONFIG_RSBAC_MAC
          case RSYS_mac_set_curr_level:
            return sys_rsbac_mac_set_curr_level(k_arg.mac_set_curr_level.level,
                                                (void __user *)(long)k_arg.mac_set_curr_level.categories_p);
          case RSYS_mac_get_curr_level:
            return sys_rsbac_mac_get_curr_level((void __user *)(long)k_arg.mac_get_curr_level.level_p,
                                                (void __user *)(long)k_arg.mac_get_curr_level.categories_p);
          case RSYS_mac_get_max_level:
            return sys_rsbac_mac_get_max_level((void __user *)(long)k_arg.mac_get_max_level.level_p,
                                               (void __user *)(long)k_arg.mac_get_max_level.categories_p);
          case RSYS_mac_get_min_level:
            return sys_rsbac_mac_get_min_level((void __user *)(long)k_arg.mac_get_min_level.level_p,
                                               (void __user *)(long)k_arg.mac_get_min_level.categories_p);
          case RSYS_mac_add_p_tru:
            return sys_rsbac_mac_add_p_tru(k_arg.mac_add_p_tru.ta_number,
                                           k_arg.mac_add_p_tru.pid,
                                           k_arg.mac_add_p_tru.uid,
                                           k_arg.mac_add_p_tru.ttl);
          case RSYS_mac_remove_p_tru:
            return sys_rsbac_mac_remove_p_tru(k_arg.mac_remove_p_tru.ta_number,
                                              k_arg.mac_remove_p_tru.pid,
                                              k_arg.mac_add_p_tru.uid);
          case RSYS_mac_add_f_tru:
            return sys_rsbac_mac_add_f_tru(k_arg.mac_add_f_tru.ta_number,
                                           (void __user *)(long)k_arg.mac_add_f_tru.filename,
                                           k_arg.mac_add_p_tru.uid,
                                           k_arg.mac_add_f_tru.ttl);
          case RSYS_mac_remove_f_tru:
            return sys_rsbac_mac_remove_f_tru(k_arg.mac_remove_f_tru.ta_number,
                                            (void __user *)(long)k_arg.mac_remove_f_tru.filename,
                                            k_arg.mac_remove_f_tru.uid);
          case RSYS_mac_get_f_trulist:
            return sys_rsbac_mac_get_f_trulist(k_arg.mac_get_f_trulist.ta_number,
                                                (void __user *)(long)k_arg.mac_get_f_trulist.filename,
                                                (void __user *)(long)k_arg.mac_get_f_trulist.trulist,
                                                (void __user *)(long)k_arg.mac_get_f_trulist.ttllist,
                                                k_arg.mac_get_f_trulist.maxnum);
          case RSYS_mac_get_p_trulist:
            return sys_rsbac_mac_get_p_trulist(k_arg.mac_get_p_trulist.ta_number,
                                               k_arg.mac_get_p_trulist.pid,
                                               (void __user *)(long)k_arg.mac_get_p_trulist.trulist,
                                               (void __user *)(long)k_arg.mac_get_p_trulist.ttllist,
                                               k_arg.mac_get_p_trulist.maxnum);
#endif
#ifdef CONFIG_RSBAC_RC
          case RSYS_rc_copy_role:
            return sys_rsbac_rc_copy_role(k_arg.rc_copy_role.ta_number,
                                          k_arg.rc_copy_role.from_role,
                                          k_arg.rc_copy_role.to_role);
          case RSYS_rc_copy_type:
            return sys_rsbac_rc_copy_type(k_arg.rc_copy_type.ta_number,
                                          k_arg.rc_copy_type.target,
                                          k_arg.rc_copy_type.from_type,
                                          k_arg.rc_copy_type.to_type);
          case RSYS_rc_set_item:
            return sys_rsbac_rc_set_item(k_arg.rc_set_item.ta_number,
                                         k_arg.rc_set_item.target,
                                         (void __user *)(long)k_arg.rc_set_item.tid_p,
                                         (void __user *)(long)k_arg.rc_set_item.subtid_p,
                                         k_arg.rc_set_item.item,
                                         (void __user *)(long)k_arg.rc_set_item.value_p,
                                         k_arg.rc_set_item.ttl);
          case RSYS_rc_get_eff_rights_n:
            return sys_rsbac_rc_get_eff_rights_n(k_arg.rc_get_eff_rights_n.ta_number,
                                                 k_arg.rc_get_eff_rights_n.target,
                                                 (void __user *)(long)k_arg.rc_get_eff_rights_n.t_name,
                                                 (void __user *)(long)k_arg.rc_get_eff_rights_n.request_vector_p,
                                                 (void __user *)(long)k_arg.rc_get_eff_rights_n.ttl_p);
          case RSYS_rc_get_list:
            return sys_rsbac_rc_get_list(k_arg.rc_get_list.ta_number,
                                         k_arg.rc_get_list.target,
                                         (void __user *)(long)k_arg.rc_get_list.tid_p,
                                         k_arg.rc_get_list.item,
                                         k_arg.rc_get_list.maxnum,
                                         (void __user *)(long)k_arg.rc_get_list.array_p,
                                         (void __user *)(long)k_arg.rc_get_list.ttl_array_p);
	case RSYS_rc_select_fd_create_type:
		return sys_rsbac_rc_select_fd_create_type(k_arg.rc_select_fd_create_type.type);
#endif
#ifdef CONFIG_RSBAC_AUTH
          case RSYS_auth_add_p_cap:
            {
              struct rsbac_auth_cap_range_t cap_range_64;

              cap_range_64.first = k_arg.auth_add_p_cap.cap_range.first;
              cap_range_64.last = k_arg.auth_add_p_cap.cap_range.last;
              return sys_rsbac_auth_add_p_cap(k_arg.auth_add_p_cap.ta_number,
                                            k_arg.auth_add_p_cap.pid,
                                            k_arg.auth_add_p_cap.cap_type,
                                            cap_range_64,
                                            k_arg.auth_add_p_cap.ttl);
            }
          case RSYS_auth_remove_p_cap:
            {
              struct rsbac_auth_cap_range_t cap_range_64;

              cap_range_64.first = k_arg.auth_add_p_cap.cap_range.first;
              cap_range_64.last = k_arg.auth_add_p_cap.cap_range.last;
              return sys_rsbac_auth_remove_p_cap(k_arg.auth_remove_p_cap.ta_number,
                                               k_arg.auth_remove_p_cap.pid,
                                               k_arg.auth_remove_p_cap.cap_type,
                                               cap_range_64);
            }
          case RSYS_auth_add_f_cap:
            {
              struct rsbac_auth_cap_range_t cap_range_64;

              cap_range_64.first = k_arg.auth_add_p_cap.cap_range.first;
              cap_range_64.last = k_arg.auth_add_p_cap.cap_range.last;
              return sys_rsbac_auth_add_f_cap(k_arg.auth_add_f_cap.ta_number,
                                            (void __user *)(long)k_arg.auth_add_f_cap.filename,
                                            k_arg.auth_add_f_cap.cap_type,
                                            cap_range_64,
                                            k_arg.auth_add_f_cap.ttl);
            }
          case RSYS_auth_remove_f_cap:
            {
              struct rsbac_auth_cap_range_t cap_range_64;

              cap_range_64.first = k_arg.auth_add_p_cap.cap_range.first;
              cap_range_64.last = k_arg.auth_add_p_cap.cap_range.last;
              return sys_rsbac_auth_remove_f_cap(k_arg.auth_remove_f_cap.ta_number,
                                               (void __user *)(long)k_arg.auth_remove_f_cap.filename,
                                               k_arg.auth_remove_f_cap.cap_type,
                                               cap_range_64);
            }
          case RSYS_auth_get_f_caplist:
            return sys_rsbac_auth_get_f_caplist(k_arg.auth_get_f_caplist.ta_number,
                                                (void __user *)(long)k_arg.auth_get_f_caplist.filename,
                                                k_arg.auth_get_f_caplist.cap_type,
                                                (void __user *)(long)k_arg.auth_get_f_caplist.caplist,
                                                (void __user *)(long)k_arg.auth_get_f_caplist.ttllist,
                                                k_arg.auth_get_f_caplist.maxnum);
          case RSYS_auth_get_p_caplist:
            return sys_rsbac_auth_get_p_caplist(k_arg.auth_get_p_caplist.ta_number,
                                                k_arg.auth_get_p_caplist.pid,
                                                k_arg.auth_get_p_caplist.cap_type,
                                                (void __user *)(long)k_arg.auth_get_p_caplist.caplist,
                                                (void __user *)(long)k_arg.auth_get_p_caplist.ttllist,
                                                k_arg.auth_get_p_caplist.maxnum);
#endif
#ifdef CONFIG_RSBAC_ACL
          case RSYS_acl:
            return sys_rsbac_acl(k_arg.acl.ta_number,
                                 k_arg.acl.call,
                                 (void __user *)(long)k_arg.acl.arg);
          case RSYS_acl_n:
            return sys_rsbac_acl_n(k_arg.acl_n.ta_number,
                                   k_arg.acl_n.call,
                                   (void __user *)(long)k_arg.acl_n.arg);
          case RSYS_acl_get_rights:
            return sys_rsbac_acl_get_rights(k_arg.acl_get_rights.ta_number,
                                            (void __user *)(long)k_arg.acl_get_rights.arg,
                                            (void __user *)(long)k_arg.acl_get_rights.rights_p,
                                            k_arg.acl_get_rights.effective);
          case RSYS_acl_get_rights_n:
            return sys_rsbac_acl_get_rights_n(k_arg.acl_get_rights_n.ta_number,
                                              (void __user *)(long)k_arg.acl_get_rights_n.arg,
                                              (void __user *)(long)k_arg.acl_get_rights_n.rights_p,
                                              k_arg.acl_get_rights_n.effective);
          case RSYS_acl_get_tlist:
            return sys_rsbac_acl_get_tlist(k_arg.acl_get_tlist.ta_number,
                                           k_arg.acl_get_tlist.target,
                                           (void __user *)(long)k_arg.acl_get_tlist.tid,
                                           (void __user *)(long)k_arg.acl_get_tlist.entry_array,
                                           (void __user *)(long)k_arg.acl_get_tlist.ttl_array,
                                           k_arg.acl_get_tlist.maxnum);
          case RSYS_acl_get_tlist_n:
            return sys_rsbac_acl_get_tlist_n(k_arg.acl_get_tlist_n.ta_number,
                                             k_arg.acl_get_tlist_n.target,
                                             (void __user *)(long)k_arg.acl_get_tlist_n.t_name,
                                             (void __user *)(long)k_arg.acl_get_tlist_n.entry_array,
                                             (void __user *)(long)k_arg.acl_get_tlist_n.ttl_array,
                                             k_arg.acl_get_tlist_n.maxnum);
          case RSYS_acl_get_mask:
            return sys_rsbac_acl_get_mask(k_arg.acl_get_mask.ta_number,
                                          k_arg.acl_get_mask.target,
                                          (void __user *)(long)k_arg.acl_get_mask.tid,
                                          (void __user *)(long)k_arg.acl_get_mask.mask_p);
          case RSYS_acl_get_mask_n:
            return sys_rsbac_acl_get_mask_n(k_arg.acl_get_mask_n.ta_number,
                                            k_arg.acl_get_mask_n.target,
                                            (void __user *)(long)k_arg.acl_get_mask_n.t_name,
                                            (void __user *)(long)k_arg.acl_get_mask_n.mask_p);
          case RSYS_acl_group:
            return sys_rsbac_acl_group(k_arg.acl_group.ta_number,
                                       k_arg.acl_group.call,
                                       (void __user *)(long)k_arg.acl_group.arg_p);
          case RSYS_acl_list_all_dev:
            return sys_rsbac_acl_list_all_dev(k_arg.acl_list_all_dev.ta_number,
                                              (void __user *)(long)k_arg.acl_list_all_dev.id_p,
                                              k_arg.acl_list_all_dev.maxnum);
          case RSYS_acl_list_all_user:
            return sys_rsbac_acl_list_all_user(k_arg.acl_list_all_user.ta_number,
                                               (void __user *)(long)k_arg.acl_list_all_user.id_p,
                                               k_arg.acl_list_all_user.maxnum);
          case RSYS_acl_list_all_group:
            return sys_rsbac_acl_list_all_group(k_arg.acl_list_all_group.ta_number,
                                                (void __user *)(long)k_arg.acl_list_all_group.id_p,
                                                k_arg.acl_list_all_group.maxnum);
#endif
#ifdef CONFIG_RSBAC_RES
          case RSYS_res_get_user_limit:
            return sys_rsbac_res_get_user_limit(k_arg.res_get_user_limit.ta_number,
                                                k_arg.res_get_user_limit.uid,
                                                k_arg.res_get_user_limit.attr,
                                                k_arg.res_get_user_limit.res_num,
                                                (void __user *)(long)k_arg.res_get_user_limit.value_p,
                                                (void __user *)(long)k_arg.res_get_user_limit.ttl_p,
                                                k_arg.res_get_user_limit.inherit);
          case RSYS_res_set_user_limit:
            return sys_rsbac_res_set_user_limit(k_arg.res_set_user_limit.ta_number,
                                                k_arg.res_set_user_limit.uid,
                                                k_arg.res_set_user_limit.attr,
                                                k_arg.res_set_user_limit.res_num,
                                                (void __user *)(long)k_arg.res_set_user_limit.value_p,
                                                k_arg.res_set_user_limit.ttl);

          case RSYS_res_get_file_limit:
            return sys_rsbac_res_get_file_limit(k_arg.res_get_file_limit.ta_number,
                                                (void __user *)(long)k_arg.res_get_file_limit.t_name,
                                                k_arg.res_get_file_limit.attr,
                                                k_arg.res_get_file_limit.res_num,
                                                (void __user *)(long)k_arg.res_get_file_limit.value_p,
                                                (void __user *)(long)k_arg.res_get_file_limit.ttl_p);

          case RSYS_res_set_file_limit:
            return sys_rsbac_res_set_file_limit(k_arg.res_set_file_limit.ta_number,
                                                (void __user *)(long)k_arg.res_set_file_limit.t_name,
                                                k_arg.res_set_file_limit.attr,
                                                k_arg.res_set_file_limit.res_num,
                                                (void __user *)(long)k_arg.res_set_file_limit.value_p,
                                                k_arg.res_set_file_limit.ttl);
#endif
#ifdef CONFIG_RSBAC_REG
          case RSYS_reg:
            return sys_rsbac_reg(k_arg.reg.handle,
                                 (void __user *)(long)k_arg.reg.arg);
#endif
#ifdef CONFIG_RSBAC_UM
          case RSYS_um_auth_name:
            return sys_rsbac_um_auth_name((void __user *)(long)k_arg.um_auth_name.name,
                                          (void __user *)(long)k_arg.um_auth_name.pass);
          case RSYS_um_auth_uid:
            return sys_rsbac_um_auth_uid(k_arg.um_auth_uid.uid,
                                         (void __user *)(long)k_arg.um_auth_uid.pass);
          case RSYS_um_add_user:
            return sys_rsbac_um_add_user(k_arg.um_add_user.ta_number,
                                         k_arg.um_add_user.uid,
                                         (void __user *)(long)k_arg.um_add_user.entry_p,
                                         (void __user *)(long)k_arg.um_add_user.pass,
                                         k_arg.um_add_user.ttl);
          case RSYS_um_add_group:
            return sys_rsbac_um_add_group(k_arg.um_add_group.ta_number,
                                          k_arg.um_add_group.gid,
                                          (void __user *)(long)k_arg.um_add_group.entry_p,
                                          (void __user *)(long)k_arg.um_add_group.pass,
                                          k_arg.um_add_group.ttl);
          case RSYS_um_add_user_hash:
            return sys_rsbac_um_add_user_hash(k_arg.um_add_user_hash.ta_number,
                                         k_arg.um_add_user_hash.uid,
                                         (void __user *)(long)k_arg.um_add_user_hash.entry_p,
                                         (void __user *)(long)k_arg.um_add_user_hash.pass,
                                         (void __user *)(long)k_arg.um_add_user_hash.hash_algo,
                                         k_arg.um_add_user_hash.ttl);
          case RSYS_um_add_group_hash:
            return sys_rsbac_um_add_group_hash(k_arg.um_add_group_hash.ta_number,
                                          k_arg.um_add_group_hash.gid,
                                          (void __user *)(long)k_arg.um_add_group_hash.entry_p,
                                          (void __user *)(long)k_arg.um_add_group_hash.pass,
                                          (void __user *)(long)k_arg.um_add_group_hash.hash_algo,
                                          k_arg.um_add_group_hash.ttl);
          case RSYS_um_add_gm:
            return sys_rsbac_um_add_gm(k_arg.um_add_gm.ta_number,
                                       k_arg.um_add_gm.uid,
                                       k_arg.um_add_gm.gid,
                                       k_arg.um_add_gm.ttl);
          case RSYS_um_mod_user:
            return sys_rsbac_um_mod_user(k_arg.um_mod_user.ta_number,
                                         k_arg.um_mod_user.uid,
                                         k_arg.um_mod_user.mod,
                                         (void __user *)(long)k_arg.um_mod_user.data_p);
          case RSYS_um_mod_group:
            return sys_rsbac_um_mod_group(k_arg.um_mod_group.ta_number,
                                          k_arg.um_mod_group.gid,
                                          k_arg.um_mod_group.mod,
                                          (void __user *)(long)k_arg.um_mod_group.data_p);
          case RSYS_um_remove_user:
            return sys_rsbac_um_remove_user(k_arg.um_remove_user.ta_number,
                                            k_arg.um_remove_user.uid);
          case RSYS_um_remove_group:
            return sys_rsbac_um_remove_group(k_arg.um_remove_group.ta_number,
                                             k_arg.um_remove_group.gid);
          case RSYS_um_remove_gm:
            return sys_rsbac_um_remove_gm(k_arg.um_remove_gm.ta_number,
                                          k_arg.um_remove_gm.uid,
                                          k_arg.um_remove_gm.gid);
          case RSYS_um_user_exists:
            return sys_rsbac_um_user_exists(k_arg.um_user_exists.ta_number,
                                            k_arg.um_user_exists.uid);
          case RSYS_um_get_next_user:
            return sys_rsbac_um_get_next_user(k_arg.um_get_next_user.ta_number,
                                              k_arg.um_get_next_user.old_user,
                                              (void __user *)(long)k_arg.um_get_next_user.next_user_p);
          case RSYS_um_group_exists:
            return sys_rsbac_um_group_exists(k_arg.um_group_exists.ta_number,
                                            k_arg.um_group_exists.gid);
          case RSYS_um_get_group_list:
            return sys_rsbac_um_get_group_list(k_arg.um_get_group_list.ta_number,
                                               k_arg.um_get_group_list.vset,
                                               (void __user *)(long)k_arg.um_get_group_list.group_array,
                                               k_arg.um_get_group_list.maxnum);
          case RSYS_um_set_pass:
            return sys_rsbac_um_set_pass(k_arg.um_set_pass.uid,
                                         (void __user *)(long)k_arg.um_set_pass.old_pass,
                                         (void __user *)(long)k_arg.um_set_pass.new_pass);
          case RSYS_um_set_pass_name:
            return sys_rsbac_um_set_pass_name((void __user *)(long)k_arg.um_set_pass_name.name,
                                         (void __user *)(long)k_arg.um_set_pass_name.old_pass,
                                         (void __user *)(long)k_arg.um_set_pass_name.new_pass);
          case RSYS_um_set_pass_hash:
            return sys_rsbac_um_set_pass_hash(k_arg.um_set_pass_hash.uid,
                                         (void __user *)(long)k_arg.um_set_pass_hash.old_pass,
                                         (void __user *)(long)k_arg.um_set_pass_hash.new_pass,
                                         (void __user *)(long)k_arg.um_set_pass_hash.hash_algo);
          case RSYS_um_set_pass_name_hash:
            return sys_rsbac_um_set_pass_name_hash((void __user *)(long)k_arg.um_set_pass_name_hash.name,
                                         (void __user *)(long)k_arg.um_set_pass_name_hash.old_pass,
                                         (void __user *)(long)k_arg.um_set_pass_name_hash.new_pass,
                                         (void __user *)(long)k_arg.um_set_pass_name_hash.hash_algo);
          case RSYS_um_add_onetime:
            return sys_rsbac_um_add_onetime(k_arg.um_add_onetime.uid,
                                         (void __user *)(long)k_arg.um_add_onetime.old_pass,
                                         (void __user *)(long)k_arg.um_add_onetime.new_pass,
                                         k_arg.um_add_onetime.ttl);
          case RSYS_um_add_onetime_name:
            return sys_rsbac_um_add_onetime_name((void __user *)(long)k_arg.um_add_onetime_name.name,
                                         (void __user *)(long)k_arg.um_add_onetime_name.old_pass,
                                         (void __user *)(long)k_arg.um_add_onetime_name.new_pass,
                                         k_arg.um_add_onetime_name.ttl);
          case RSYS_um_add_onetime_hash:
            return sys_rsbac_um_add_onetime_hash(k_arg.um_add_onetime_hash.uid,
                                         (void __user *)(long)k_arg.um_add_onetime_hash.old_pass,
                                         (void __user *)(long)k_arg.um_add_onetime_hash.new_pass,
                                         (void __user *)(long)k_arg.um_add_onetime_hash.hash_algo,
                                         k_arg.um_add_onetime_hash.ttl);
          case RSYS_um_add_onetime_name_hash:
            return sys_rsbac_um_add_onetime_name_hash((void __user *)(long)k_arg.um_add_onetime_name_hash.name,
                                         (void __user *)(long)k_arg.um_add_onetime_name_hash.old_pass,
                                         (void __user *)(long)k_arg.um_add_onetime_name_hash.new_pass,
                                         (void __user *)(long)k_arg.um_add_onetime_name_hash.hash_algo,
                                         k_arg.um_add_onetime_name_hash.ttl);
          case RSYS_um_remove_all_onetime:
            return sys_rsbac_um_remove_all_onetime(k_arg.um_remove_all_onetime.uid,
                                         (void __user *)(long)k_arg.um_remove_all_onetime.old_pass);
          case RSYS_um_remove_all_onetime_name:
            return sys_rsbac_um_remove_all_onetime_name((void __user *)(long)k_arg.um_remove_all_onetime_name.name,
                                         (void __user *)(long)k_arg.um_remove_all_onetime_name.old_pass);
          case RSYS_um_count_onetime:
            return sys_rsbac_um_count_onetime(k_arg.um_count_onetime.uid,
                                         (void __user *)(long)k_arg.um_count_onetime.old_pass);
          case RSYS_um_count_onetime_name:
            return sys_rsbac_um_count_onetime_name((void __user *)(long)k_arg.um_count_onetime_name.name,
                                         (void __user *)(long)k_arg.um_count_onetime_name.old_pass);
          case RSYS_um_set_group_pass:
            return sys_rsbac_um_set_group_pass(k_arg.um_set_group_pass.gid,
                                               (void __user *)(long)k_arg.um_set_group_pass.new_pass);
          case RSYS_um_set_group_pass_hash:
            return sys_rsbac_um_set_group_pass_hash(k_arg.um_set_group_pass_hash.gid,
                                               (void __user *)(long)k_arg.um_set_group_pass_hash.new_pass,
                                               (void __user *)(long)k_arg.um_set_group_pass_hash.hash_algo);
          case RSYS_um_check_account:
            return sys_rsbac_um_check_account(k_arg.um_check_account.uid);
          case RSYS_um_get_max_history:
            return sys_rsbac_um_get_max_history(k_arg.um_get_max_history.ta_number,
                                                k_arg.um_get_max_history.uid);
          case RSYS_um_get_max_history_name:
            return sys_rsbac_um_get_max_history_name(k_arg.um_get_max_history_name.ta_number,
                                                     (void __user *)(long)k_arg.um_get_max_history_name.name);
          case RSYS_um_set_max_history:
            return sys_rsbac_um_set_max_history(k_arg.um_set_max_history.ta_number,
                                                k_arg.um_set_max_history.uid,
                                                k_arg.um_set_max_history.max_history);
          case RSYS_um_set_max_history_name:
            return sys_rsbac_um_set_max_history_name(k_arg.um_set_max_history_name.ta_number,
                                                (void __user *)(long)k_arg.um_set_max_history_name.name,
                                                k_arg.um_set_max_history_name.max_history);
          case RSYS_um_select_vset:
            return sys_rsbac_um_select_vset(k_arg.um_select_vset.vset);
#endif
#ifdef CONFIG_RSBAC_UDF
          case RSYS_udf_flush_cache:
            return sys_rsbac_udf_flush_cache();
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
          case RSYS_list_ta_begin_name:
            return sys_rsbac_list_ta_begin_name(k_arg.list_ta_begin.ttl,
                                           (void __user *)(long)k_arg.list_ta_begin_name.ta_number_p,
                                           k_arg.list_ta_begin_name.commit_uid,
                                           (void __user *)(long)k_arg.list_ta_begin_name.name,
                                           (void __user *)(long)k_arg.list_ta_begin_name.password);
          case RSYS_list_ta_begin:
            return sys_rsbac_list_ta_begin(k_arg.list_ta_begin.ttl,
                                           (void __user *)(long)k_arg.list_ta_begin.ta_number_p,
                                           k_arg.list_ta_begin.commit_uid,
                                           (void __user *)(long)k_arg.list_ta_begin.password);
          case RSYS_list_ta_refresh:
            return sys_rsbac_list_ta_refresh(k_arg.list_ta_refresh.ttl,
                                             k_arg.list_ta_refresh.ta_number,
                                             (void __user *)(long)k_arg.list_ta_refresh.password);
          case RSYS_list_ta_commit:
            return sys_rsbac_list_ta_commit(k_arg.list_ta_commit.ta_number,
                                            (void __user *)(long)k_arg.list_ta_commit.password);
          case RSYS_list_ta_forget:
            return sys_rsbac_list_ta_forget(k_arg.list_ta_forget.ta_number,
                                            (void __user *)(long)k_arg.list_ta_forget.password);
#endif

          case RSYS_list_all_dev:
            return sys_rsbac_list_all_dev(k_arg.list_all_dev.ta_number,
                                          (void __user *)(long)k_arg.list_all_dev.id_p,
                                          k_arg.list_all_dev.maxnum);
          case RSYS_list_all_user:
            return sys_rsbac_list_all_user(k_arg.list_all_user.ta_number,
                                           (void __user *)(long)k_arg.list_all_user.id_p,
                                           k_arg.list_all_user.maxnum);
          case RSYS_list_all_group:
            return sys_rsbac_list_all_group(k_arg.list_all_group.ta_number,
                                            (void __user *)(long)k_arg.list_all_group.id_p,
                                            k_arg.list_all_group.maxnum);
	case RSYS_list_all_ipc:
		return sys_rsbac_list_all_ipc(k_arg.list_all_ipc.ta_number,
					       (void __user *)(long)k_arg.list_all_ipc.id_p,
					       k_arg.list_all_ipc.maxnum);

          case RSYS_version:
            return RSBAC_VERSION_NR;
          case RSYS_api_min_version:
            return RSBAC_API_MIN_VERSION_NR;
          case RSYS_api_max_version:
            return RSBAC_API_MAX_VERSION_NR;
          case RSYS_stats:
            return sys_rsbac_stats();
          case RSYS_check:
            return sys_rsbac_check(k_arg.check.correct, k_arg.check.check_inode);
#if defined(CONFIG_RSBAC_INIT_DELAY)
          case RSYS_init:
            return sys_rsbac_init((void __user *)(long)k_arg.init.root_dev);
#endif

          default:
            return -RSBAC_EINVALIDREQUEST;
        }
    } else
#endif
    {
      union rsbac_syscall_arg_t k_arg;

      /* get values from user space */
      if(arg_p)
        {
          err = rsbac_get_user(&k_arg, arg_p, sizeof(k_arg) );
          if(unlikely(err < 0))
            return err;
        }
      else
        {
          memset(&k_arg, 0, sizeof(k_arg));
        }

      switch(call)
        {
#ifdef CONFIG_RSBAC_UM
          case RSYS_um_get_user_item:
            return sys_rsbac_um_get_user_item(k_arg.um_get_user_item.ta_number,
                                              k_arg.um_get_user_item.uid,
                                              k_arg.um_get_user_item.mod,
                                              k_arg.um_get_user_item.data_p);
          case RSYS_um_get_uid:
            return sys_rsbac_um_get_uid(k_arg.um_get_uid.ta_number,
                                        k_arg.um_get_uid.name,
                                        k_arg.um_get_uid.uid_p);
          case RSYS_um_get_group_item:
            return sys_rsbac_um_get_group_item(k_arg.um_get_group_item.ta_number,
                                               k_arg.um_get_group_item.gid,
                                               k_arg.um_get_group_item.mod,
                                               k_arg.um_get_group_item.data_p);
          case RSYS_um_get_gm_list:
            return sys_rsbac_um_get_gm_list(k_arg.um_get_gm_list.ta_number,
                                            k_arg.um_get_gm_list.user,
                                            k_arg.um_get_gm_list.group_array,
                                            k_arg.um_get_gm_list.maxnum);
          case RSYS_um_get_gm_user_list:
            return sys_rsbac_um_get_gm_user_list(k_arg.um_get_gm_user_list.ta_number,
                                                 k_arg.um_get_gm_user_list.group,
                                                 k_arg.um_get_gm_user_list.user_array,
                                                 k_arg.um_get_gm_user_list.maxnum);
          case RSYS_um_get_gid:
            return sys_rsbac_um_get_gid(k_arg.um_get_gid.ta_number,
                                        k_arg.um_get_gid.name,
                                        k_arg.um_get_gid.gid_p);
          case RSYS_um_get_user_list:
            return sys_rsbac_um_get_user_list(k_arg.um_get_user_list.ta_number,
                                              k_arg.um_get_user_list.vset,
                                              k_arg.um_get_user_list.user_array,
                                              k_arg.um_get_user_list.maxnum);
          case RSYS_um_check_account_name:
            return sys_rsbac_um_check_account_name(k_arg.um_check_account_name.name);
#endif
          case RSYS_get_attr:
            return sys_rsbac_get_attr(k_arg.get_attr.ta_number,
                                      k_arg.get_attr.module,
                                      k_arg.get_attr.target,
                                      k_arg.get_attr.tid,
                                      k_arg.get_attr.attr,
                                      k_arg.get_attr.value,
                                      k_arg.get_attr.inherit);
          case RSYS_get_attr_n:
            return sys_rsbac_get_attr_n(k_arg.get_attr_n.ta_number,
                                        k_arg.get_attr_n.module,
                                        k_arg.get_attr_n.target,
                                        k_arg.get_attr_n.t_name,
                                        k_arg.get_attr_n.attr,
                                        k_arg.get_attr_n.value,
                                        k_arg.get_attr_n.inherit);
          case RSYS_set_attr:
            return sys_rsbac_set_attr(k_arg.set_attr.ta_number,
                                      k_arg.set_attr.module,
                                      k_arg.set_attr.target,
                                      k_arg.set_attr.tid,
                                      k_arg.set_attr.attr,
                                      k_arg.set_attr.value);
          case RSYS_set_attr_n:
            return sys_rsbac_set_attr_n(k_arg.set_attr_n.ta_number,
                                        k_arg.set_attr_n.module,
                                        k_arg.set_attr_n.target,
                                        k_arg.set_attr_n.t_name,
                                        k_arg.set_attr_n.attr,
                                        k_arg.set_attr_n.value);
#ifdef CONFIG_RSBAC_RC
          case RSYS_rc_get_current_role:
            return sys_rsbac_rc_get_current_role(k_arg.rc_get_current_role.role_p);
          case RSYS_rc_get_item:
            return sys_rsbac_rc_get_item(k_arg.rc_get_item.ta_number,
                                         k_arg.rc_get_item.target,
                                         k_arg.rc_get_item.tid_p,
                                         k_arg.rc_get_item.subtid_p,
                                         k_arg.rc_get_item.item,
                                         k_arg.rc_get_item.value_p,
                                         k_arg.rc_get_item.ttl_p);
          case RSYS_rc_change_role:
            return sys_rsbac_rc_change_role(k_arg.rc_change_role.role, k_arg.rc_change_role.pass);
#endif
#ifdef CONFIG_RSBAC_JAIL
          case RSYS_jail:
            return rsbac_jail_sys_jail(k_arg.jail.version,
                                       k_arg.jail.path,
                                       k_arg.jail.ip,
                                       k_arg.jail.flags,
                                       k_arg.jail.max_caps,
                                       k_arg.jail.scd_get,
                                       k_arg.jail.scd_modify);
#endif

          case RSYS_remove_target:
            return sys_rsbac_remove_target(k_arg.remove_target.ta_number,
                                           k_arg.remove_target.target,
                                           k_arg.remove_target.tid);
          case RSYS_remove_target_n:
            return sys_rsbac_remove_target_n(k_arg.remove_target_n.ta_number,
                                             k_arg.remove_target_n.target,
                                             k_arg.remove_target_n.t_name);
          case RSYS_net_list_all_netdev:
            return sys_rsbac_net_list_all_netdev(k_arg.net_list_all_netdev.ta_number,
                                                 k_arg.net_list_all_netdev.id_p,
                                                 k_arg.net_list_all_netdev.maxnum);
          case RSYS_net_template:
            return sys_rsbac_net_template(k_arg.net_template.ta_number,
                                          k_arg.net_template.call,
                                          k_arg.net_template.id,
                                          k_arg.net_template.data_p);
          case RSYS_net_list_all_template:
            return sys_rsbac_net_list_all_template(k_arg.net_list_all_template.ta_number,
                                                   k_arg.net_list_all_template.id_p,
                                                   k_arg.net_list_all_template.maxnum);
          case RSYS_switch:
            return sys_rsbac_switch(k_arg.switch_module.module,
                                    k_arg.switch_module.value);
	case RSYS_get_switch:
	  return sys_rsbac_get_switch(k_arg.get_switch_module.module,
			  		k_arg.get_switch_module.value_p,
					k_arg.get_switch_module.switchable_p);
          case RSYS_adf_log_switch:
            return sys_rsbac_adf_log_switch(k_arg.adf_log_switch.request,
                                            k_arg.adf_log_switch.target,
                                            k_arg.adf_log_switch.value);
          case RSYS_get_adf_log:
            return sys_rsbac_get_adf_log(k_arg.get_adf_log.request,
                                         k_arg.get_adf_log.target,
                                         k_arg.get_adf_log.value_p);
          case RSYS_write:
            return sys_rsbac_write();
          case RSYS_log:
            return sys_rsbac_log(k_arg.log.type,
                                 k_arg.log.buf,
                                 k_arg.log.len);
#ifdef CONFIG_RSBAC_MAC
          case RSYS_mac_set_curr_level:
            return sys_rsbac_mac_set_curr_level(k_arg.mac_set_curr_level.level,
                                                k_arg.mac_set_curr_level.categories_p);
          case RSYS_mac_get_curr_level:
            return sys_rsbac_mac_get_curr_level(k_arg.mac_get_curr_level.level_p,
                                                k_arg.mac_get_curr_level.categories_p);
          case RSYS_mac_get_max_level:
            return sys_rsbac_mac_get_max_level(k_arg.mac_get_max_level.level_p,
                                               k_arg.mac_get_max_level.categories_p);
          case RSYS_mac_get_min_level:
            return sys_rsbac_mac_get_min_level(k_arg.mac_get_min_level.level_p,
                                               k_arg.mac_get_min_level.categories_p);
          case RSYS_mac_add_p_tru:
            return sys_rsbac_mac_add_p_tru(k_arg.mac_add_p_tru.ta_number,
                                           k_arg.mac_add_p_tru.pid,
                                           k_arg.mac_add_p_tru.uid,
                                           k_arg.mac_add_p_tru.ttl);
          case RSYS_mac_remove_p_tru:
            return sys_rsbac_mac_remove_p_tru(k_arg.mac_remove_p_tru.ta_number,
                                              k_arg.mac_remove_p_tru.pid,
                                              k_arg.mac_add_p_tru.uid);
          case RSYS_mac_add_f_tru:
            return sys_rsbac_mac_add_f_tru(k_arg.mac_add_f_tru.ta_number,
                                           k_arg.mac_add_f_tru.filename,
                                           k_arg.mac_add_p_tru.uid,
                                           k_arg.mac_add_f_tru.ttl);
          case RSYS_mac_remove_f_tru:
            return sys_rsbac_mac_remove_f_tru(k_arg.mac_remove_f_tru.ta_number,
                                            k_arg.mac_remove_f_tru.filename,
                                            k_arg.mac_remove_f_tru.uid);
          case RSYS_mac_get_f_trulist:
            return sys_rsbac_mac_get_f_trulist(k_arg.mac_get_f_trulist.ta_number,
                                                k_arg.mac_get_f_trulist.filename,
                                                k_arg.mac_get_f_trulist.trulist,
                                                k_arg.mac_get_f_trulist.ttllist,
                                                k_arg.mac_get_f_trulist.maxnum);
          case RSYS_mac_get_p_trulist:
            return sys_rsbac_mac_get_p_trulist(k_arg.mac_get_p_trulist.ta_number,
                                               k_arg.mac_get_p_trulist.pid,
                                               k_arg.mac_get_p_trulist.trulist,
                                               k_arg.mac_get_p_trulist.ttllist,
                                               k_arg.mac_get_p_trulist.maxnum);
#endif
#ifdef CONFIG_RSBAC_RC
          case RSYS_rc_copy_role:
            return sys_rsbac_rc_copy_role(k_arg.rc_copy_role.ta_number,
                                          k_arg.rc_copy_role.from_role,
                                          k_arg.rc_copy_role.to_role);
          case RSYS_rc_copy_type:
            return sys_rsbac_rc_copy_type(k_arg.rc_copy_type.ta_number,
                                          k_arg.rc_copy_type.target,
                                          k_arg.rc_copy_type.from_type,
                                          k_arg.rc_copy_type.to_type);
          case RSYS_rc_set_item:
            return sys_rsbac_rc_set_item(k_arg.rc_set_item.ta_number,
                                         k_arg.rc_set_item.target,
                                         k_arg.rc_set_item.tid_p,
                                         k_arg.rc_set_item.subtid_p,
                                         k_arg.rc_set_item.item,
                                         k_arg.rc_set_item.value_p,
                                         k_arg.rc_set_item.ttl);
          case RSYS_rc_get_eff_rights_n:
            return sys_rsbac_rc_get_eff_rights_n(k_arg.rc_get_eff_rights_n.ta_number,
                                                 k_arg.rc_get_eff_rights_n.target,
                                                 k_arg.rc_get_eff_rights_n.t_name,
                                                 k_arg.rc_get_eff_rights_n.request_vector_p,
                                                 k_arg.rc_get_eff_rights_n.ttl_p);
          case RSYS_rc_get_list:
            return sys_rsbac_rc_get_list(k_arg.rc_get_list.ta_number,
                                         k_arg.rc_get_list.target,
                                         k_arg.rc_get_list.tid_p,
                                         k_arg.rc_get_list.item,
                                         k_arg.rc_get_list.maxnum,
                                         k_arg.rc_get_list.array_p,
                                         k_arg.rc_get_list.ttl_array_p);
	case RSYS_rc_select_fd_create_type:
		return sys_rsbac_rc_select_fd_create_type(k_arg.rc_select_fd_create_type.type);
#endif
#ifdef CONFIG_RSBAC_AUTH
          case RSYS_auth_add_p_cap:
            return sys_rsbac_auth_add_p_cap(k_arg.auth_add_p_cap.ta_number,
                                            k_arg.auth_add_p_cap.pid,
                                            k_arg.auth_add_p_cap.cap_type,
                                            k_arg.auth_add_p_cap.cap_range,
                                            k_arg.auth_add_p_cap.ttl);
          case RSYS_auth_remove_p_cap:
            return sys_rsbac_auth_remove_p_cap(k_arg.auth_remove_p_cap.ta_number,
                                               k_arg.auth_remove_p_cap.pid,
                                               k_arg.auth_remove_p_cap.cap_type,
                                               k_arg.auth_remove_p_cap.cap_range);
          case RSYS_auth_add_f_cap:
            return sys_rsbac_auth_add_f_cap(k_arg.auth_add_f_cap.ta_number,
                                            k_arg.auth_add_f_cap.filename,
                                            k_arg.auth_add_f_cap.cap_type,
                                            k_arg.auth_add_f_cap.cap_range,
                                            k_arg.auth_add_f_cap.ttl);
          case RSYS_auth_remove_f_cap:
            return sys_rsbac_auth_remove_f_cap(k_arg.auth_remove_f_cap.ta_number,
                                               k_arg.auth_remove_f_cap.filename,
                                               k_arg.auth_remove_f_cap.cap_type,
                                               k_arg.auth_remove_f_cap.cap_range);
          case RSYS_auth_get_f_caplist:
            return sys_rsbac_auth_get_f_caplist(k_arg.auth_get_f_caplist.ta_number,
                                                k_arg.auth_get_f_caplist.filename,
                                                k_arg.auth_get_f_caplist.cap_type,
                                                k_arg.auth_get_f_caplist.caplist,
                                                k_arg.auth_get_f_caplist.ttllist,
                                                k_arg.auth_get_f_caplist.maxnum);
          case RSYS_auth_get_p_caplist:
            return sys_rsbac_auth_get_p_caplist(k_arg.auth_get_p_caplist.ta_number,
                                                k_arg.auth_get_p_caplist.pid,
                                                k_arg.auth_get_p_caplist.cap_type,
                                                k_arg.auth_get_p_caplist.caplist,
                                                k_arg.auth_get_p_caplist.ttllist,
                                                k_arg.auth_get_p_caplist.maxnum);
#endif
#ifdef CONFIG_RSBAC_ACL
          case RSYS_acl:
            return sys_rsbac_acl(k_arg.acl.ta_number,
                                 k_arg.acl.call,
                                 k_arg.acl.arg);
          case RSYS_acl_n:
            return sys_rsbac_acl_n(k_arg.acl_n.ta_number,
                                   k_arg.acl_n.call,
                                   k_arg.acl_n.arg);
          case RSYS_acl_get_rights:
            return sys_rsbac_acl_get_rights(k_arg.acl_get_rights.ta_number,
                                            k_arg.acl_get_rights.arg,
                                            k_arg.acl_get_rights.rights_p,
                                            k_arg.acl_get_rights.effective);
          case RSYS_acl_get_rights_n:
            return sys_rsbac_acl_get_rights_n(k_arg.acl_get_rights_n.ta_number,
                                              k_arg.acl_get_rights_n.arg,
                                              k_arg.acl_get_rights_n.rights_p,
                                              k_arg.acl_get_rights_n.effective);
          case RSYS_acl_get_tlist:
            return sys_rsbac_acl_get_tlist(k_arg.acl_get_tlist.ta_number,
                                           k_arg.acl_get_tlist.target,
                                           k_arg.acl_get_tlist.tid,
                                           k_arg.acl_get_tlist.entry_array,
                                           k_arg.acl_get_tlist.ttl_array,
                                           k_arg.acl_get_tlist.maxnum);
          case RSYS_acl_get_tlist_n:
            return sys_rsbac_acl_get_tlist_n(k_arg.acl_get_tlist_n.ta_number,
                                             k_arg.acl_get_tlist_n.target,
                                             k_arg.acl_get_tlist_n.t_name,
                                             k_arg.acl_get_tlist_n.entry_array,
                                             k_arg.acl_get_tlist_n.ttl_array,
                                             k_arg.acl_get_tlist_n.maxnum);
          case RSYS_acl_get_mask:
            return sys_rsbac_acl_get_mask(k_arg.acl_get_mask.ta_number,
                                          k_arg.acl_get_mask.target,
                                          k_arg.acl_get_mask.tid,
                                          k_arg.acl_get_mask.mask_p);
          case RSYS_acl_get_mask_n:
            return sys_rsbac_acl_get_mask_n(k_arg.acl_get_mask_n.ta_number,
                                            k_arg.acl_get_mask_n.target,
                                            k_arg.acl_get_mask_n.t_name,
                                            k_arg.acl_get_mask_n.mask_p);
          case RSYS_acl_group:
            return sys_rsbac_acl_group(k_arg.acl_group.ta_number,
                                       k_arg.acl_group.call,
                                       k_arg.acl_group.arg_p);
          case RSYS_acl_list_all_dev:
            return sys_rsbac_acl_list_all_dev(k_arg.acl_list_all_dev.ta_number,
                                              k_arg.acl_list_all_dev.id_p,
                                              k_arg.acl_list_all_dev.maxnum);
          case RSYS_acl_list_all_user:
            return sys_rsbac_acl_list_all_user(k_arg.acl_list_all_user.ta_number,
                                               k_arg.acl_list_all_user.id_p,
                                               k_arg.acl_list_all_user.maxnum);
          case RSYS_acl_list_all_group:
            return sys_rsbac_acl_list_all_group(k_arg.acl_list_all_group.ta_number,
                                                k_arg.acl_list_all_group.id_p,
                                                k_arg.acl_list_all_group.maxnum);
#endif
#ifdef CONFIG_RSBAC_RES
          case RSYS_res_get_user_limit:
            return sys_rsbac_res_get_user_limit(k_arg.res_get_user_limit.ta_number,
                                                k_arg.res_get_user_limit.uid,
                                                k_arg.res_get_user_limit.attr,
                                                k_arg.res_get_user_limit.res_num,
                                                k_arg.res_get_user_limit.value_p,
                                                k_arg.res_get_user_limit.ttl_p,
                                                k_arg.res_get_user_limit.inherit);
          case RSYS_res_set_user_limit:
            return sys_rsbac_res_set_user_limit(k_arg.res_set_user_limit.ta_number,
                                                k_arg.res_set_user_limit.uid,
                                                k_arg.res_set_user_limit.attr,
                                                k_arg.res_set_user_limit.res_num,
                                                k_arg.res_set_user_limit.value_p,
                                                k_arg.res_set_user_limit.ttl);

          case RSYS_res_get_file_limit:
            return sys_rsbac_res_get_file_limit(k_arg.res_get_file_limit.ta_number,
                                                k_arg.res_get_file_limit.t_name,
                                                k_arg.res_get_file_limit.attr,
                                                k_arg.res_get_file_limit.res_num,
                                                k_arg.res_get_file_limit.value_p,
                                                k_arg.res_get_file_limit.ttl_p);

          case RSYS_res_set_file_limit:
            return sys_rsbac_res_set_file_limit(k_arg.res_set_file_limit.ta_number,
                                                k_arg.res_set_file_limit.t_name,
                                                k_arg.res_set_file_limit.attr,
                                                k_arg.res_set_file_limit.res_num,
                                                k_arg.res_set_file_limit.value_p,
                                                k_arg.res_set_file_limit.ttl);
#endif
#ifdef CONFIG_RSBAC_REG
          case RSYS_reg:
            return sys_rsbac_reg(k_arg.reg.handle,
                                 k_arg.reg.arg);
#endif
#ifdef CONFIG_RSBAC_UM
          case RSYS_um_auth_name:
            return sys_rsbac_um_auth_name(k_arg.um_auth_name.name,
                                          k_arg.um_auth_name.pass);
          case RSYS_um_auth_uid:
            return sys_rsbac_um_auth_uid(k_arg.um_auth_uid.uid,
                                         k_arg.um_auth_uid.pass);
          case RSYS_um_add_user:
            return sys_rsbac_um_add_user(k_arg.um_add_user.ta_number,
                                         k_arg.um_add_user.uid,
                                         k_arg.um_add_user.entry_p,
                                         k_arg.um_add_user.pass,
                                         k_arg.um_add_user.ttl);
          case RSYS_um_add_group:
            return sys_rsbac_um_add_group(k_arg.um_add_group.ta_number,
                                          k_arg.um_add_group.gid,
                                          k_arg.um_add_group.entry_p,
                                          k_arg.um_add_group.pass,
                                          k_arg.um_add_group.ttl);
          case RSYS_um_add_user_hash:
            return sys_rsbac_um_add_user_hash(k_arg.um_add_user_hash.ta_number,
                                         k_arg.um_add_user_hash.uid,
                                         k_arg.um_add_user_hash.entry_p,
                                         k_arg.um_add_user_hash.pass,
                                         k_arg.um_add_user_hash.hash_algo,
                                         k_arg.um_add_user_hash.ttl);
          case RSYS_um_add_group_hash:
            return sys_rsbac_um_add_group_hash(k_arg.um_add_group_hash.ta_number,
                                          k_arg.um_add_group_hash.gid,
                                          k_arg.um_add_group_hash.entry_p,
                                          k_arg.um_add_group_hash.pass,
                                          k_arg.um_add_group_hash.hash_algo,
                                          k_arg.um_add_group_hash.ttl);
          case RSYS_um_add_gm:
            return sys_rsbac_um_add_gm(k_arg.um_add_gm.ta_number,
                                       k_arg.um_add_gm.uid,
                                       k_arg.um_add_gm.gid,
                                       k_arg.um_add_gm.ttl);
          case RSYS_um_mod_user:
            return sys_rsbac_um_mod_user(k_arg.um_mod_user.ta_number,
                                         k_arg.um_mod_user.uid,
                                         k_arg.um_mod_user.mod,
                                         k_arg.um_mod_user.data_p);
          case RSYS_um_mod_group:
            return sys_rsbac_um_mod_group(k_arg.um_mod_group.ta_number,
                                          k_arg.um_mod_group.gid,
                                          k_arg.um_mod_group.mod,
                                          k_arg.um_mod_group.data_p);
          case RSYS_um_remove_user:
            return sys_rsbac_um_remove_user(k_arg.um_remove_user.ta_number,
                                            k_arg.um_remove_user.uid);
          case RSYS_um_remove_group:
            return sys_rsbac_um_remove_group(k_arg.um_remove_group.ta_number,
                                             k_arg.um_remove_group.gid);
          case RSYS_um_remove_gm:
            return sys_rsbac_um_remove_gm(k_arg.um_remove_gm.ta_number,
                                          k_arg.um_remove_gm.uid,
                                          k_arg.um_remove_gm.gid);
          case RSYS_um_user_exists:
            return sys_rsbac_um_user_exists(k_arg.um_user_exists.ta_number,
                                            k_arg.um_user_exists.uid);
          case RSYS_um_get_next_user:
            return sys_rsbac_um_get_next_user(k_arg.um_get_next_user.ta_number,
                                              k_arg.um_get_next_user.old_user,
                                              k_arg.um_get_next_user.next_user_p);
          case RSYS_um_group_exists:
            return sys_rsbac_um_group_exists(k_arg.um_group_exists.ta_number,
                                            k_arg.um_group_exists.gid);
          case RSYS_um_get_group_list:
            return sys_rsbac_um_get_group_list(k_arg.um_get_group_list.ta_number,
                                               k_arg.um_get_group_list.vset,
                                               k_arg.um_get_group_list.group_array,
                                               k_arg.um_get_group_list.maxnum);
          case RSYS_um_set_pass:
            return sys_rsbac_um_set_pass(k_arg.um_set_pass.uid,
                                         k_arg.um_set_pass.old_pass,
                                         k_arg.um_set_pass.new_pass);
          case RSYS_um_set_pass_name:
            return sys_rsbac_um_set_pass_name(k_arg.um_set_pass_name.name,
                                         k_arg.um_set_pass_name.old_pass,
                                         k_arg.um_set_pass_name.new_pass);
          case RSYS_um_set_pass_hash:
            return sys_rsbac_um_set_pass_hash(k_arg.um_set_pass_hash.uid,
                                         k_arg.um_set_pass_hash.old_pass,
                                         k_arg.um_set_pass_hash.new_pass,
                                         k_arg.um_set_pass_hash.hash_algo);
          case RSYS_um_set_pass_name_hash:
            return sys_rsbac_um_set_pass_name_hash(k_arg.um_set_pass_name_hash.name,
                                         k_arg.um_set_pass_name_hash.old_pass,
                                         k_arg.um_set_pass_name_hash.new_pass,
                                         k_arg.um_set_pass_name_hash.hash_algo);
          case RSYS_um_add_onetime:
            return sys_rsbac_um_add_onetime(k_arg.um_add_onetime.uid,
                                         k_arg.um_add_onetime.old_pass,
                                         k_arg.um_add_onetime.new_pass,
                                         k_arg.um_add_onetime.ttl);
          case RSYS_um_add_onetime_name:
            return sys_rsbac_um_add_onetime_name(k_arg.um_add_onetime_name.name,
                                         k_arg.um_add_onetime_name.old_pass,
                                         k_arg.um_add_onetime_name.new_pass,
                                         k_arg.um_add_onetime_name.ttl);
          case RSYS_um_add_onetime_hash:
            return sys_rsbac_um_add_onetime_hash(k_arg.um_add_onetime_hash.uid,
                                         k_arg.um_add_onetime_hash.old_pass,
                                         k_arg.um_add_onetime_hash.new_pass,
                                         k_arg.um_add_onetime_hash.hash_algo,
                                         k_arg.um_add_onetime_hash.ttl);
          case RSYS_um_add_onetime_name_hash:
            return sys_rsbac_um_add_onetime_name_hash(k_arg.um_add_onetime_name_hash.name,
                                         k_arg.um_add_onetime_name_hash.old_pass,
                                         k_arg.um_add_onetime_name_hash.new_pass,
                                         k_arg.um_add_onetime_name_hash.hash_algo,
                                         k_arg.um_add_onetime_name_hash.ttl);
          case RSYS_um_remove_all_onetime:
            return sys_rsbac_um_remove_all_onetime(k_arg.um_remove_all_onetime.uid,
                                         k_arg.um_remove_all_onetime.old_pass);
          case RSYS_um_remove_all_onetime_name:
            return sys_rsbac_um_remove_all_onetime_name(k_arg.um_remove_all_onetime_name.name,
                                         k_arg.um_remove_all_onetime_name.old_pass);
          case RSYS_um_count_onetime:
            return sys_rsbac_um_count_onetime(k_arg.um_count_onetime.uid,
                                         k_arg.um_count_onetime.old_pass);
          case RSYS_um_count_onetime_name:
            return sys_rsbac_um_count_onetime_name(k_arg.um_count_onetime_name.name,
                                         k_arg.um_count_onetime_name.old_pass);
          case RSYS_um_set_group_pass:
            return sys_rsbac_um_set_group_pass(k_arg.um_set_group_pass.gid,
                                               k_arg.um_set_group_pass.new_pass);
          case RSYS_um_set_group_pass_hash:
            return sys_rsbac_um_set_group_pass_hash(k_arg.um_set_group_pass_hash.gid,
                                               k_arg.um_set_group_pass_hash.new_pass,
                                               k_arg.um_set_group_pass_hash.hash_algo);
          case RSYS_um_check_account:
            return sys_rsbac_um_check_account(k_arg.um_check_account.uid);
          case RSYS_um_get_max_history:
            return sys_rsbac_um_get_max_history(k_arg.um_get_max_history.ta_number,
                                                k_arg.um_get_max_history.uid);
          case RSYS_um_get_max_history_name:
            return sys_rsbac_um_get_max_history_name(k_arg.um_get_max_history_name.ta_number,
                                                     k_arg.um_get_max_history_name.name);
          case RSYS_um_set_max_history:
            return sys_rsbac_um_set_max_history(k_arg.um_set_max_history.ta_number,
                                                k_arg.um_set_max_history.uid,
                                                k_arg.um_set_max_history.max_history);
          case RSYS_um_set_max_history_name:
            return sys_rsbac_um_set_max_history_name(k_arg.um_set_max_history_name.ta_number,
                                                k_arg.um_set_max_history_name.name,
                                                k_arg.um_set_max_history_name.max_history);
          case RSYS_um_select_vset:
            return sys_rsbac_um_select_vset(k_arg.um_select_vset.vset);
#endif
#ifdef CONFIG_RSBAC_UDF
          case RSYS_udf_flush_cache:
            return sys_rsbac_udf_flush_cache();
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
          case RSYS_list_ta_begin_name:
            return sys_rsbac_list_ta_begin_name(k_arg.list_ta_begin.ttl,
                                           k_arg.list_ta_begin_name.ta_number_p,
                                           k_arg.list_ta_begin_name.commit_uid,
                                           k_arg.list_ta_begin_name.name,
                                           k_arg.list_ta_begin_name.password);
          case RSYS_list_ta_begin:
            return sys_rsbac_list_ta_begin(k_arg.list_ta_begin.ttl,
                                           k_arg.list_ta_begin.ta_number_p,
                                           k_arg.list_ta_begin.commit_uid,
                                           k_arg.list_ta_begin.password);
          case RSYS_list_ta_refresh:
            return sys_rsbac_list_ta_refresh(k_arg.list_ta_refresh.ttl,
                                             k_arg.list_ta_refresh.ta_number,
                                             k_arg.list_ta_refresh.password);
          case RSYS_list_ta_commit:
            return sys_rsbac_list_ta_commit(k_arg.list_ta_commit.ta_number,
                                            k_arg.list_ta_commit.password);
          case RSYS_list_ta_forget:
            return sys_rsbac_list_ta_forget(k_arg.list_ta_forget.ta_number,
                                            k_arg.list_ta_forget.password);
#endif

          case RSYS_list_all_dev:
            return sys_rsbac_list_all_dev(k_arg.list_all_dev.ta_number,
                                          k_arg.list_all_dev.id_p,
                                          k_arg.list_all_dev.maxnum);
          case RSYS_list_all_user:
            return sys_rsbac_list_all_user(k_arg.list_all_user.ta_number,
                                           k_arg.list_all_user.id_p,
                                           k_arg.list_all_user.maxnum);
          case RSYS_list_all_group:
            return sys_rsbac_list_all_group(k_arg.list_all_group.ta_number,
                                            k_arg.list_all_group.id_p,
                                            k_arg.list_all_group.maxnum);
	case RSYS_list_all_ipc:
		return sys_rsbac_list_all_ipc(k_arg.list_all_ipc.
					       ta_number,
					       k_arg.list_all_ipc.id_p,
					       k_arg.list_all_ipc.maxnum);

          case RSYS_version:
            return RSBAC_VERSION_NR;
          case RSYS_api_min_version:
            return RSBAC_API_MIN_VERSION_NR;
          case RSYS_api_max_version:
            return RSBAC_API_MAX_VERSION_NR;
          case RSYS_stats:
            return sys_rsbac_stats();
          case RSYS_check:
            return sys_rsbac_check(k_arg.check.correct, k_arg.check.check_inode);
#if defined(CONFIG_RSBAC_INIT_DELAY)
          case RSYS_init:
            return sys_rsbac_init(k_arg.init.root_dev);
#endif

          default:
            return -RSBAC_EINVALIDREQUEST;
        }
      }
    }

/* end of syscalls.c */
