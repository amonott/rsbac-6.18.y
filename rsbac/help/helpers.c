/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2025:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Helper functions for all parts      */
/* Last modified: 15/Dec/2025          */
/************************************* */

#include <rsbac/types.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/rc_types.h>
#include <rsbac/getname.h>
#include <rsbac/cap_getname.h>
#include <rsbac/adf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <uapi/linux/magic.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <rsbac/aci.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#ifdef CONFIG_RSBAC_RC
#include <rsbac/rc_getname.h>
#endif

int rsbac_get_vset_num(char * sourcename, rsbac_um_set_t * vset_p)
  {
    if (!sourcename || !vset_p)
      return -RSBAC_EINVALIDPOINTER;
    if (!strcmp(sourcename,"all")) {
      *vset_p = RSBAC_UM_VIRTUAL_ALL;
      return 0;
    }
    if (!strcmp(sourcename,"auto") || !strcmp(sourcename,"keep")) {
      *vset_p = RSBAC_UM_VIRTUAL_KEEP;
      return 0;
    }
    *vset_p = simple_strtoul(sourcename, NULL, 0);
    if(!*vset_p && strcmp(sourcename,"0"))
      return -RSBAC_EINVALIDVALUE;
    if (*vset_p > RSBAC_UM_VIRTUAL_MAX)
      return -RSBAC_EINVALIDVALUE;
    return 0;
  }

char * inttostr(char * str, int i)
  {
    int j = 0;
    
    if(!str)
      return(NULL);
      
    if (i<0)
      {
        str[j] = '-';
        j++;
        i = -i;
      }
    if (i>=10000)
      {
        str[j] = '0' + (i / 10000);
        j++;
      }
    if (i>=1000)
      {
        str[j] = '0' + ((i % 10000) / 1000);
        j++;
      }
    if (i>=100)
      {
        str[j] = '0' + ((i % 1000) / 100);
        j++;
      }
    if (i>=10)
      {
        str[j] = '0' + ((i % 100) / 10);
        j++;
      }
    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * ulongtostr(char * str, u_long i)
  {
    int    j = 0;
    u_long k = 1000000000;
    
    if(!str)
      return(NULL);

    if (i>=k)
      {
        str[j] = '0' + ((i / k) % 100);
        j++;
      }
    k /= 10;

    while (k>1)
      {
        if (i>=k)
          {
            str[j] = '0' + ((i % (k*10)) / k);
            j++;
          }
        k /= 10;
      };

    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * longtostr(char * str, long i)
  {
    int    j = 0;
    u_long k = 1000000000;
    
    if(!str)
      return(NULL);

    if (i<0)
      {
        str[0] = '-';
        j = 1;
        i = -i;
      }
    if (i>=k)
      {
        str[j] = '0' + ((i / k) % 100);
        j++;
      }
    k /= 10;

    while (k>1)
      {
        if (i>=k)
          {
            str[j] = '0' + ((i % (k*10)) / k);
            j++;
          }
        k /= 10;
      };

    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * u64tostrmac(char * str, __u64 i)
  {
    int    j = 0;
    __u64  k;

    if(!str)
      return(NULL);

    k = 1;
    for(j = RSBAC_MAC_MAX_CAT;j >= 0;j--)
      {
        if (i & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[RSBAC_MAC_NR_CATS] = 0;
    return (str);
  };

char * u64tostracl(char * str, __u64 i)
  {
    int    j = 0;
    __u64  k;

    if(!str)
      return(NULL);

    k = 1;
    for(j = ACLR_NONE - 1;j >= 0;j--)
      {
        if (i & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[ACLR_NONE] = 0;
    return (str);
  };

#ifdef CONFIG_RSBAC_UM_VIRTUAL
rsbac_um_set_t rsbac_get_vset(void)
  {
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    i_tid.process = task_pid(current);
    if(rsbac_get_attr(SW_GEN,
                        T_PROCESS,
                        i_tid,
                        A_vset,
                        &i_attr_val,
                        TRUE))
	return 0;
    else
    	return i_attr_val.vset;
  }
#endif

/* find the current owner of this process */
void rsbac_get_owner(rsbac_uid_t * user_p)
  {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    *user_p = RSBAC_GEN_UID(rsbac_get_vset(), __kuid_val(current_uid()));
#else
    *user_p = __kuid_val(current_uid());
#endif
  }

void rsbac_ds_get_error(const char * function, enum rsbac_attribute_t attr)
  {
    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() returned error!\n",
                     function);
      }
  }

void rsbac_ds_get_error_num(const char * function, enum rsbac_attribute_t attr, int err)
  {
    char tmp2[80];

    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() for %s returned error %s!\n",
                     function, tmp, tmp2);
      }
    else
      {
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() returned error %s!\n",
                     function, tmp2);
      }
  }

void rsbac_ds_set_error(const char * function, enum rsbac_attribute_t attr)
  {
    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() returned error!\n",
                     function);
      }
  }

void rsbac_ds_set_error_num(const char * function, enum rsbac_attribute_t attr, int err)
  {
    char tmp2[80];

    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() for %s returned error %s!\n",
                     function, tmp, tmp2);
      }
    else
      {
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() returned error %s!\n",
                     function, tmp2);
      }
  }

#ifdef CONFIG_RSBAC_RC
void rsbac_rc_ds_get_error(const char * function, enum rsbac_rc_item_t item)
  {
    if(!function)
      return;
    if(item != RI_none)
      {
        char tmp[80];

        get_rc_item_name(tmp, item);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_get_item() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_get_item() returned error!\n",
                     function);
      }
  }

void rsbac_rc_ds_set_error(const char * function, enum rsbac_rc_item_t item)
  {
    if(!function)
      return;
    if(item != RI_none)
      {
        char tmp[80];

        get_rc_item_name(tmp, item);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_set_item() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_set_item() returned error!\n",
                     function);
      }
  }
#endif

#if defined(CONFIG_RSBAC_CAP_FD_HIDE)
EXPORT_SYMBOL(rsbac_cap_hide_fd);
rsbac_boolean_t rsbac_cap_hide_fd(struct inode * target_inode)
{
	union  rsbac_target_id_t       rsbac_target_id;
	union  rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_cap_fd_hiding)
		return FALSE;

	rsbac_target_id.process = task_pid(current);
	/* kernel and init are never blocked */
	if (pid_nr(rsbac_target_id.process) < 2)
		return FALSE;

	if (!target_inode || !target_inode->i_sb) {
		return FALSE;
	}
	/* special case: procfs has misleading owner/mode values, e.g for fd dir */
	if (target_inode->i_sb->s_magic == PROC_SUPER_MAGIC)
		return FALSE;

	if (uid_eq(target_inode->i_uid, current_uid()))
		return FALSE;
	if (uid_eq(target_inode->i_uid, current_euid()))
		return FALSE;
	if (uid_eq(target_inode->i_uid, current_fsuid()))
		return FALSE;
	/* always take the fast track, Ceph was the only special case and
	   it does not handle too many requests well */
	if (!generic_permission(&nop_mnt_idmap, target_inode, MAY_READ))
		return FALSE;
	if (!generic_permission(&nop_mnt_idmap, target_inode, MAY_EXEC))
		return FALSE;
	if (!generic_permission(&nop_mnt_idmap, target_inode, MAY_WRITE))
		return FALSE;

	rsbac_get_owner(&rsbac_target_id.user);
	if (unlikely(rsbac_get_attr(SW_CAP,
			T_USER,
			rsbac_target_id,
			A_cap_role,
			&rsbac_attribute_value,
			FALSE))) {
		rsbac_ds_get_error("rsbac_cap_hide_fd()", A_cap_role);
		return FALSE;  /* something weird happened */
	}
	if (   rsbac_attribute_value.system_role == SR_security_officer
	    || rsbac_attribute_value.system_role == SR_administrator
	)
		return FALSE;

#ifdef CONFIG_RSBAC_SOFTMODE
	if(   rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	   || rsbac_ind_softmode[SW_CAP]
#endif
	) {
#if 0
		rsbac_pr_debug(adf_cap, "running in softmode, FD hiding not applied to process %u(%s) with owner %u!\n",
				pid_nr(task_pid(current)),
				current->comm,
				current_uid());
#endif
		return FALSE;
	}
#endif

	rsbac_pr_debug(adf_cap, "FD hiding: process %u(%s), process uid %u, dev %02u:%02u, inode %u, owner %u, mode %o!\n",
			pid_nr(task_pid(current)),
			current->comm,
			current_uid(),
			target_inode->i_sb ? RSBAC_MAJOR(target_inode->i_sb->s_dev) : RSBAC_AUTO_DEV_NUM,
			target_inode->i_sb ? RSBAC_MINOR(target_inode->i_sb->s_dev) : RSBAC_AUTO_DEV_NUM,
			target_inode->i_ino,
			target_inode->i_uid,
			target_inode->i_mode);
	return TRUE;
}

#endif

#if defined(CONFIG_RSBAC_FSOBJ_HIDE) || defined(CONFIG_RSBAC_CAP_FD_HIDE)
int rsbac_handle_filldir(const struct file *file, const char *name, const unsigned int namlen, const ino_t ino)
{
#if defined(CONFIG_RSBAC_FSOBJ_HIDE)
	enum   rsbac_target_t	       rsbac_target = T_NONE;
	union  rsbac_target_id_t       rsbac_target_id;
	union  rsbac_attribute_value_t rsbac_attribute_value;
#endif
	struct dentry *obj_dentry = NULL;
	int err = 1;

	if(!rsbac_initialized) {
		goto old_func;
	}

	if(!name || !file || !file->f_path.dentry || !file->f_path.dentry->d_sb
		 || !MAJOR(file->f_path.dentry->d_sb->s_dev) || file->f_path.dentry->d_sb->s_magic == MSDOS_SUPER_MAGIC)
		goto old_func;

        if (in_interrupt())
          {
            printk(KERN_WARNING "rsbac_handle_filldir(): called from interrupt: pid %u(%s)!\n",
                         current->pid, current->comm);
            goto old_func;
          }

	obj_dentry = lookup_one(&nop_mnt_idmap, &QSTR(name), file->f_path.dentry);
	if (!obj_dentry || IS_ERR(obj_dentry)) {
		goto old_func;
	}
	if (!obj_dentry->d_inode || IS_ERR(obj_dentry->d_inode)) {
		goto out_dput;
	}
	if (!obj_dentry->d_inode->i_mode || !obj_dentry->d_inode->i_sb || !obj_dentry->d_inode->i_sb->s_dev || !ino) {
		goto out_dput;
	}
	if (!obj_dentry->d_sb || !obj_dentry->d_sb->s_magic) {
		goto out_dput;
	}

#if defined(CONFIG_RSBAC_CAP_FD_HIDE)
	if (rsbac_cap_hide_fd(obj_dentry->d_inode)) {
		err = 0;
		goto out_dput;
	}
#endif

#if defined(CONFIG_RSBAC_FSOBJ_HIDE)
	rsbac_pr_debug(aef, "[readdir(), sys_getdents()]: calling ADF\n");

	if (S_ISFIFO(obj_dentry->d_inode->i_mode)) {
		if(obj_dentry->d_sb->s_magic != PIPEFS_MAGIC) {
			rsbac_target = T_FIFO;
			rsbac_target_id.fifo.device = obj_dentry->d_inode->i_sb->s_dev;
			rsbac_target_id.fifo.inode  = ino;
			rsbac_target_id.fifo.dentry_p = obj_dentry;
		}
	} else
	if (S_ISDIR(obj_dentry->d_inode->i_mode)) {
		rsbac_target = T_DIR;
		rsbac_target_id.dir.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.dir.inode = ino;
		rsbac_target_id.dir.dentry_p = obj_dentry;
	} else
	if (S_ISLNK(obj_dentry->d_inode->i_mode)) {
		rsbac_target = T_SYMLINK;
		rsbac_target_id.file.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.file.inode = ino;
		rsbac_target_id.file.dentry_p = obj_dentry;
	} else
	if (S_ISSOCK(obj_dentry->d_inode->i_mode)) {
		if (obj_dentry->d_inode->i_sb->s_magic != SOCKFS_MAGIC) {
			rsbac_target = T_UNIXSOCK;
			rsbac_target_id.unixsock.device = obj_dentry->d_inode->i_sb->s_dev;
			rsbac_target_id.unixsock.inode = ino;
			rsbac_target_id.unixsock.dentry_p = obj_dentry;
		}
	} else {
		rsbac_target = T_FILE;
		rsbac_target_id.file.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.file.inode = ino;
		rsbac_target_id.file.dentry_p = obj_dentry;
	}
	rsbac_attribute_value.dummy = 0;
	if (rsbac_target != T_NONE)
		if (!rsbac_adf_request(R_SEARCH,
					task_pid(current),
					rsbac_target,
					rsbac_target_id,
					A_none,
					rsbac_attribute_value))
		{
			err = 0;
			goto out_dput;
		}
#endif

out_dput:
	if (obj_dentry)
		dput(obj_dentry);
old_func:
	return err;
}
#endif

int rsbac_handle_rw_req(const struct file *file, struct rsbac_rw_req *rsbac_rw_req_obj)
{
	int err = 1;

	if(!rsbac_initialized) {
		goto out;
	}

/*	if (rsbac_rw_req_obj->rsbac_target != T_NONE){printk("i'm here! going out because of target ! =T_NONE\n");
                goto out;}
*/
	if(!file || !file->f_path.dentry || !file->f_path.dentry->d_sb
		 || !MAJOR(file->f_path.dentry->d_sb->s_dev)
		 || !file->f_path.dentry->d_sb->s_magic
		 || !file->f_path.dentry->d_inode
		 || IS_ERR(file->f_path.dentry->d_inode)
		 || !file->f_path.dentry->d_inode->i_mode
		 || !file->f_path.dentry->d_inode->i_ino)
		goto out;

        if (in_interrupt())
          {
            printk(KERN_WARNING "rsbac_handle_rw_req(): called from interrupt: pid %u(%s)!\n",
                         current->pid, current->comm);
            goto out;
          }

	rsbac_pr_debug(aef, "rsbac_handle_rw_req(): calling ADF\n");

	rsbac_rw_req_obj->rsbac_attribute = A_none;
        rsbac_rw_req_obj->rsbac_attribute_value.dummy = 0;

	if (S_ISFIFO(file->f_path.dentry->d_inode->i_mode)) {
		if(file->f_path.dentry->d_sb->s_magic != PIPEFS_MAGIC) {
			rsbac_rw_req_obj->rsbac_target = T_FIFO;
			rsbac_rw_req_obj->rsbac_target_id.fifo.device = file->f_path.dentry->d_inode->i_sb->s_dev;
			rsbac_rw_req_obj->rsbac_target_id.fifo.inode  = file->f_path.dentry->d_inode->i_ino;
			rsbac_rw_req_obj->rsbac_target_id.fifo.dentry_p = file->f_path.dentry;
		}
	} else
	if (file->f_path.dentry->d_inode->i_rsbac_memfd) {
		rsbac_rw_req_obj->rsbac_target = T_IPC;
		rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_memfd;
		rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = file->f_path.dentry->d_inode->i_ino;
	} else
	if (S_ISREG(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_FILE;
		rsbac_rw_req_obj->rsbac_target_id.file.device = file->f_path.dentry->d_inode->i_sb->s_dev;
		rsbac_rw_req_obj->rsbac_target_id.file.inode  = file->f_path.dentry->d_inode->i_ino;
		rsbac_rw_req_obj->rsbac_target_id.file.dentry_p = file->f_path.dentry;
	} else
	if (S_ISSOCK(file->f_path.dentry->d_inode->i_mode)) {
		struct socket * sock = SOCKET_I(file->f_path.dentry->d_inode);
		if (sock->ops && (sock->ops->family == AF_UNIX)) {
			if (sock->sk) {
				if (unix_sk(unix_sk(sock->sk)->peer)) {
					if (unix_sk(unix_sk(sock->sk)->peer)->path.dentry && unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode) {
						rsbac_rw_req_obj->rsbac_target = T_UNIXSOCK;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.device = unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_sb->s_dev;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.inode  = unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode->i_ino;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.dentry_p = unix_sk(unix_sk(sock->sk)->peer)->path.dentry;
					} else {
						rsbac_rw_req_obj->rsbac_target = T_IPC;
						rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_anonunix;
						if (unix_sk(unix_sk(sock->sk)->peer)->path.dentry
								&& unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode
								&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file
                                                        	&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry
                                                        	&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry->d_inode)
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry->d_inode->i_ino;
						else
							if (sock->file && sock->file->f_path.dentry && sock->file->f_path.dentry->d_inode)
								rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = sock->file->f_path.dentry->d_inode->i_ino;
						else
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = 0;
					}
				} else {
					if (unix_sk(sock->sk)->path.dentry && unix_sk(sock->sk)->path.dentry->d_inode) {
						rsbac_rw_req_obj->rsbac_target = T_UNIXSOCK;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.device = unix_sk(sock->sk)->path.dentry->d_sb->s_dev;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.inode  = unix_sk(sock->sk)->path.dentry->d_inode->i_ino;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.dentry_p = unix_sk(sock->sk)->path.dentry;
					} else {
						rsbac_rw_req_obj->rsbac_target = T_IPC;
						rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_anonunix;
						if (sock->file && sock->file->f_path.dentry && sock->file->f_path.dentry->d_inode)
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = sock->file->f_path.dentry->d_inode->i_ino;
						else
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = 0;
					}
				}
				if (sock->sk->sk_peer_pid) {
					rsbac_rw_req_obj->rsbac_attribute = A_process;
					rsbac_rw_req_obj->rsbac_attribute_value.process = sock->sk->sk_peer_pid;
				}
				else if (unix_sk(sock->sk)->peer && unix_sk(sock->sk)->peer->sk_peer_pid) {
					rsbac_rw_req_obj->rsbac_attribute = A_process;
					rsbac_rw_req_obj->rsbac_attribute_value.process = unix_sk(sock->sk)->peer->sk_peer_pid;
				} else {
					rsbac_rw_req_obj->rsbac_attribute = A_sock_type;
					rsbac_rw_req_obj->rsbac_attribute_value.sock_type = sock->type;
				}
			}
		}
	} else
	if (S_ISBLK(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_DEV;
		rsbac_rw_req_obj->rsbac_target_id.dev.type = D_block;
		rsbac_rw_req_obj->rsbac_target_id.dev.major = RSBAC_MAJOR(file->f_path.dentry->d_inode->i_rdev);
		rsbac_rw_req_obj->rsbac_target_id.dev.minor = RSBAC_MINOR(file->f_path.dentry->d_inode->i_rdev);
	} else
	if (S_ISCHR(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_DEV;
		rsbac_rw_req_obj->rsbac_target_id.dev.type = D_char;
                rsbac_rw_req_obj->rsbac_target_id.dev.major = RSBAC_MAJOR(file->f_path.dentry->d_inode->i_rdev);
                rsbac_rw_req_obj->rsbac_target_id.dev.minor = RSBAC_MINOR(file->f_path.dentry->d_inode->i_rdev);
	}
	if (rsbac_rw_req_obj->rsbac_target != T_NONE)
		if (!rsbac_adf_request(rsbac_rw_req_obj->rsbac_request,
					task_pid(current),
					rsbac_rw_req_obj->rsbac_target,
					rsbac_rw_req_obj->rsbac_target_id,
					A_none,
					rsbac_rw_req_obj->rsbac_attribute_value))
		{
			err = 0;
			goto out;
		}

out:
	return err;
}

int rsbac_handle_rw_up(struct rsbac_rw_req *rsbac_rw_req_obj)
{
	int err = 0;

	if (rsbac_rw_req_obj->rsbac_target != T_NONE) {
		rsbac_rw_req_obj->rsbac_new_target_id.dummy = 0;
		err = rsbac_adf_set_attr(rsbac_rw_req_obj->rsbac_request,
					task_pid(current),
					rsbac_rw_req_obj->rsbac_target,
					rsbac_rw_req_obj->rsbac_target_id,
					T_NONE,
					rsbac_rw_req_obj->rsbac_new_target_id,
					rsbac_rw_req_obj->rsbac_attribute,
					rsbac_rw_req_obj->rsbac_attribute_value);
		if (err)
			rsbac_printk(KERN_WARNING "rsbac_handle_rw_up(): rsbac_adf_set_attr() returned error\n");
	}

	return err;
}
