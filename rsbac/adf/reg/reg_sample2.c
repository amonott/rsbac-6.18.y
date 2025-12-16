/*
 * RSBAC REG decision module sample2
 *
 * Author and (c) 1999-2025 Amon Ott <ao@rsbac.org>
 */

/* general stuff */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/seq_file.h>
/* for file access */
#include <linux/fs.h>
/* rsbac */
#include <rsbac/types.h>
#include <rsbac/reg.h>
#include <rsbac/adf.h>
#include <rsbac/aci.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/getname.h>
#include <rsbac/error.h>
#include <rsbac/proc_fs.h>

static u_long nr_request_calls = 0;
static u_long nr_set_attr_calls = 0;
static rsbac_boolean_t no_write = FALSE;
static u_long nr_system_calls = 0;
static void * system_call_arg = 0;

MODULE_AUTHOR("Amon Ott");
MODULE_DESCRIPTION("RSBAC REG sample decision module 2");
MODULE_LICENSE("GPL");

static char * name = NULL;
static char * syscall_name = NULL;
static long handle = 133457;
static long syscall_registration_handle = 754331;
static long syscall_dispatcher_handle = 3;

module_param(name, charp, 0000);
MODULE_PARM_DESC(name, "Name");
module_param(syscall_name, charp, 0000);
MODULE_PARM_DESC(syscall_name, "Syscall name");
module_param(handle, long, S_IRUSR);
MODULE_PARM_DESC(handle, "Handle");
module_param(syscall_registration_handle, long, S_IRUSR);
MODULE_PARM_DESC(syscall_registration_handle, "Syscall registration handle");
module_param(syscall_dispatcher_handle, long, S_IRUSR);
MODULE_PARM_DESC(syscall_dispatcher_handle, "Syscall dispatcher handle");

/* Filename for persistent data in /rsbac dir of ROOT_DEV (max 7 chars) */
#define FILENAME "regsmp2"

/* Version number for on disk data structures */
#define FILE_VERSION 1

/* PROC functions */

#if defined(CONFIG_RSBAC_PROC)
#define PROC_NAME "reg_sample2"
static int
adf_sample_proc_show(struct seq_file *m, void *v)
{
  union rsbac_target_id_t       rsbac_target_id;
  union rsbac_attribute_value_t rsbac_attribute_value;

  if (!rsbac_is_initialized())
    return -ENOSYS;

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
  seq_printf(m, "RSBAC REG decision module sample 2\n----------------------------------\n");
  seq_printf(m, "%lu calls to request function.\n",
                 nr_request_calls);
  seq_printf(m, "%lu calls to set_attr function.\n",
                 nr_set_attr_calls);
  seq_printf(m, "%lu calls to system_call function %lu, last arg was %p.\n",
                 nr_system_calls,
                 syscall_dispatcher_handle,
                 system_call_arg);
  return 0;
}

static int adf_sample_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, adf_sample_proc_show, NULL);
}

static const struct proc_ops adf_sample_proc_ops = {
       .proc_open      = adf_sample_proc_open,
       .proc_read      = seq_read,
       .proc_lseek     = seq_lseek,
       .proc_release   = single_release,
};

static struct proc_dir_entry *adf_sample;
#endif /* CONFIG_RSBAC_PROC */


/**** Read/Write Functions ****/

/* read_info() */
/* reading the system wide adf_sample2 data */

static int read_info(void)
  {
    long                            file_fd;
    char                            name[RSBAC_MAXNAMELEN];
    int                             err = 0;
    int                             tmperr;
    u_int                           version;
    u_long                          tmpval;

    /* copy name from base name */
    strcpy(name, FILENAME);

    /* open file */
    if ((file_fd = rsbac_read_open(name,
                                   RSBAC_MAJOR(rsbac_root_dev),
                                   RSBAC_MINOR(rsbac_root_dev)) ) < 0)
      return file_fd;

    /* OK, now we can start reading */

    /* There is a read function for this file, so read data from
     * previous module load.
     * A positive read return value means a read success,
     * 0 end of file and a negative value an error.
     */

    tmperr = rsbac_read_file(file_fd,
                        (char *) &version,
                        sizeof(version));
    /* error? */
    if (tmperr < sizeof(version))
      {
        rsbac_printk(KERN_WARNING
               "read_info(): read error from file!\n");
        err = -RSBAC_EREADFAILED;
        goto end_read;
      }
    /* if wrong version, warn and skip */
    if (version != FILE_VERSION)
      {
        rsbac_printk(KERN_WARNING
               "read_info(): wrong version %u, expected %u - skipping file and setting no_write!\n",
               version, FILE_VERSION);
        no_write = TRUE;
        err = -RSBAC_EREADFAILED;
        goto end_read;
      }

    /* read nr_request_calls */
    tmperr = rsbac_read_file(file_fd,
                        (char *) &tmpval,
                        sizeof(tmpval));
    if (tmperr < sizeof(tmpval))
      {
        rsbac_printk(KERN_WARNING "%s\n",
               "read_info(): read error from file!");
        err = -RSBAC_EREADFAILED;
        goto end_read;
      }
    nr_request_calls = tmpval;

    /* read nr_set_attr_calls */
    tmperr = rsbac_read_file(file_fd,
                        (char *) &tmpval,
                        sizeof(tmpval));
    if (tmperr < sizeof(tmpval))
      {
        rsbac_printk(KERN_WARNING "%s\n",
               "read_info(): read error from file!");
        err = -RSBAC_EREADFAILED;
        goto end_read;
      }
    nr_set_attr_calls = tmpval;

end_read:
    /* We do not need this file any more */
    rsbac_read_close(file_fd);

    /* ready */
    return err;
  }; /* end of read_info() */

static int write_info(void)
  {
    long                            file_fd;
    char                            name[RSBAC_MAXNAMELEN];
    int                             err = 0;
    int                             tmperr;
    u_int                           version = FILE_VERSION;
    
    /* copy name from base name */
    strcpy(name, FILENAME);

    /* open file */
    if ((file_fd = rsbac_write_open(name,
                                    RSBAC_MAJOR(rsbac_root_dev),
                                    RSBAC_MINOR(rsbac_root_dev)) ) < 0)
    {
      return file_fd;
    }

    /* OK, now we can start writing all sample items.
     * A positive return value means a write success,
     * 0 end of file and a negative value an error.
     */

    tmperr = rsbac_write_file(file_fd,
                         (char *) &version,
                         sizeof(version));
    if (tmperr < sizeof(version))
      {
        rsbac_printk(KERN_WARNING
               "write_info(): write error %i on file!\n",
               tmperr);
        err = -RSBAC_EWRITEFAILED;
        goto end_write;
      }

    tmperr = rsbac_write_file(file_fd,
                         (char *) &nr_request_calls,
                         sizeof(nr_request_calls));
    if (tmperr < sizeof(nr_request_calls))
      {
        rsbac_printk(KERN_WARNING
               "write_info(): write error %i on file!\n",
               tmperr);
        err = -RSBAC_EWRITEFAILED;
        goto end_write;
      }

    tmperr = rsbac_write_file(file_fd,
                         (char *) &nr_set_attr_calls,
                         sizeof(nr_set_attr_calls));
    if (tmperr < sizeof(nr_set_attr_calls))
      {
        rsbac_printk(KERN_WARNING
               "write_info(): write error %i on file!\n",
               tmperr);
        err = -RSBAC_EWRITEFAILED;
        goto end_write;
      }

end_write:
    /* End of write access */
    rsbac_write_close(file_fd);
    return(err);
  }; /* end of write_info() */


/**** Decision Functions ****/

static  int request_func  ( enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             owner_pid,
                            enum  rsbac_target_t          target,
                            union rsbac_target_id_t       tid,
                            enum  rsbac_attribute_t       attr,
                            union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t                   owner)
  {
    /* count call, but not for SEARCH request */
    if(request != R_SEARCH)
      nr_request_calls++;
    return GRANTED;
  }

static  int set_attr_func ( enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             owner_pid,
                            enum  rsbac_target_t          target,
                            union rsbac_target_id_t       tid,
                            enum  rsbac_target_t          new_target,
                            union rsbac_target_id_t       new_tid,
                            enum  rsbac_attribute_t       attr,
                            union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t                   owner)
  {
    /* count call, but not for SEARCH request */
    if(request != R_SEARCH)
      nr_set_attr_calls++;
    return 0;
  }

static int write_func(rsbac_boolean_t need_lock)
  {
    int res=0;

    if(!write_info())
      res = 1;

    return(res);
  }

static int syscall_func (void * arg)
  {
    nr_system_calls++;
    system_call_arg = arg;
    return nr_system_calls;
   }

/**** Init ****/

int init_module(void)
{
  struct rsbac_reg_entry_t entry;
  struct rsbac_reg_syscall_entry_t syscall_entry;

  if(!handle)
    handle = 123457;
  if(!syscall_registration_handle)
    syscall_registration_handle = 754321;
  if(!syscall_dispatcher_handle)
    syscall_dispatcher_handle = 2;

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Initializing.\n");

  /* clearing registration entries */
  memset(&entry, 0, sizeof(entry));
  memset(&syscall_entry, 0, sizeof(syscall_entry));

  if(name)
    {
      strncpy(entry.name, name, RSBAC_REG_NAME_LEN);
      entry.name[RSBAC_REG_NAME_LEN] = 0;
    }
  else
    strcpy(entry.name, "RSBAC REG sample 2 ADF module");
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: REG Version: %u, Name: %s, Handle: %li\n",
         RSBAC_REG_VERSION, entry.name, handle);

  entry.handle = handle;
  entry.request_func = request_func;
  entry.set_attr_func = set_attr_func;
  entry.write_func = write_func;
  entry.switch_on = TRUE;

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Registering to ADF.\n");
  if(rsbac_reg_register(RSBAC_REG_VERSION, entry) < 0)
    {
      rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 2: Registering failed. Unloading.\n");
      return -ENOEXEC;
    }

  if(syscall_name)
    {
      strncpy(syscall_entry.name, syscall_name, RSBAC_REG_NAME_LEN);
      syscall_entry.name[RSBAC_REG_NAME_LEN] = 0;
    }
  else
    strcpy(syscall_entry.name, "RSBAC REG sample 2 syscall");
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: REG Version: %u, Name: %s, Dispatcher Handle: %li\n",
         RSBAC_REG_VERSION, syscall_entry.name, syscall_dispatcher_handle);

  syscall_entry.registration_handle = syscall_registration_handle;
  syscall_entry.dispatcher_handle = syscall_dispatcher_handle;
  syscall_entry.syscall_func = syscall_func;

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Registering syscall.\n");
  syscall_registration_handle = rsbac_reg_register_syscall(RSBAC_REG_VERSION, syscall_entry);
  if(syscall_registration_handle < 0)
    {
      rsbac_printk(KERN_WARNING "RSBAC REG decision module sample 2: Registering syscall failed. Unloading.\n");
      if(rsbac_reg_unregister(handle))
        {
          rsbac_printk(KERN_ERR "RSBAC REG decision module sample 2: Unregistering failed - beware of possible system failure!\n");
        }
      return -ENOEXEC;
    }

  if(read_info())
    {
      rsbac_printk(KERN_WARNING
             "RSBAC REG decision module sample 2: Could not read info from previous session.\n");
    }
  
  #if defined(CONFIG_RSBAC_PROC)
  adf_sample = proc_create(PROC_NAME,  S_IFREG | S_IRUGO, proc_rsbac_root_p, &adf_sample_proc_ops);
  #endif 

  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Loaded.\n");

  return 0;
}

void cleanup_module(void)
{
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Unregistering.\n");
  #if defined(CONFIG_RSBAC_PROC)
  remove_proc_entry(PROC_NAME, proc_rsbac_root_p);
  #endif 
  if(write_info())
    {
      rsbac_printk(KERN_WARNING
             "RSBAC REG decision module sample 2: Could not save info for next session.\n");
    }
  if(rsbac_reg_unregister_syscall(syscall_registration_handle))
    {
      rsbac_printk(KERN_ERR "RSBAC REG decision module sample 2: Unregistering syscall failed - beware of possible system failure!\n");
    }
  if(rsbac_reg_unregister(handle))
    {
      rsbac_printk(KERN_ERR "RSBAC REG decision module sample 2: Unregistering module failed - beware of possible system failure!\n");
    }
  rsbac_printk(KERN_INFO "RSBAC REG decision module sample 2: Unloaded.\n");
}
