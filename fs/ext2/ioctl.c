// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext2/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include "ext2.h"
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <linux/fileattr.h>

#ifdef CONFIG_RSBAC
#include <net/sock.h>
#include <rsbac/hooks.h>
#endif

int ext2_fileattr_get(struct dentry *dentry, struct file_kattr *fa)
{
	struct ext2_inode_info *ei = EXT2_I(d_inode(dentry));

	fileattr_fill_flags(fa, ei->i_flags & EXT2_FL_USER_VISIBLE);

	return 0;
}

int ext2_fileattr_set(struct mnt_idmap *idmap,
		      struct dentry *dentry, struct file_kattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct ext2_inode_info *ei = EXT2_I(inode);

	if (fileattr_has_fsx(fa))
		return -EOPNOTSUPP;

	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		return -EPERM;

	ei->i_flags = (ei->i_flags & ~EXT2_FL_USER_MODIFIABLE) |
		(fa->flags & EXT2_FL_USER_MODIFIABLE);

	ext2_set_inode_flags(inode);
	inode_set_ctime_current(inode);
	mark_inode_dirty(inode);

	return 0;
}


long ext2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct ext2_inode_info *ei = EXT2_I(inode);
	unsigned short rsv_window_size;
	int ret;

#ifdef CONFIG_RSBAC
	enum  rsbac_adf_request_t rsbac_request;
	enum  rsbac_target_t rsbac_target = T_NONE;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
#endif

#ifdef CONFIG_RSBAC
	rsbac_pr_debug(aef, "calling ADF\n");
	switch (cmd) {
		case EXT2_IOC_GETVERSION:
		case EXT2_IOC_GETRSVSZ:
			rsbac_request = R_GET_PERMISSIONS_DATA;
			break;
		case EXT2_IOC_SETVERSION:
		case EXT2_IOC_SETRSVSZ:
			rsbac_request = R_MODIFY_PERMISSIONS_DATA;
			break;
		default:
			rsbac_request = R_NONE;
	}
	if(S_ISSOCK(inode->i_mode)) {
		if(SOCKET_I(inode)->ops
				&& (SOCKET_I(inode)->ops->family == AF_UNIX)) {
			rsbac_target = T_UNIXSOCK;
			rsbac_target_id.unixsock.device = filp->f_path.dentry->d_sb->s_dev;
			rsbac_target_id.unixsock.inode  = inode->i_ino;
			rsbac_target_id.unixsock.dentry_p = filp->f_path.dentry;
		}
#ifdef CONFIG_RSBAC_NET_OBJ
		else {
			rsbac_target = T_NETOBJ;
			rsbac_target_id.netobj.sock_p
				= SOCKET_I(inode);
			rsbac_target_id.netobj.local_addr = NULL;
			rsbac_target_id.netobj.local_len = 0;
			rsbac_target_id.netobj.remote_addr = NULL;
			rsbac_target_id.netobj.remote_len = 0;
		}
#endif
	}
	else {
		rsbac_target = T_DEV;
		rsbac_target_id.dev.type = D_block;
		rsbac_target_id.dev.major = RSBAC_MAJOR(filp->f_path.dentry->d_sb->s_dev);
		rsbac_target_id.dev.minor = RSBAC_MINOR(filp->f_path.dentry->d_sb->s_dev);
	}
	rsbac_attribute_value.ioctl_cmd = cmd;
	if(   (rsbac_request != R_NONE)
			&& !rsbac_adf_request(rsbac_request,
				task_pid(current),
				rsbac_target,
				rsbac_target_id,
				A_ioctl_cmd,
				rsbac_attribute_value))
	{
		return -EPERM;
	}
#endif

	ext2_debug ("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case EXT2_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *) arg);
	case EXT2_IOC_SETVERSION: {
		__u32 generation;

		if (!inode_owner_or_capable(&nop_mnt_idmap, inode))
			return -EPERM;
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;
		if (get_user(generation, (int __user *) arg)) {
			ret = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		inode_set_ctime_current(inode);
		inode->i_generation = generation;
		inode_unlock(inode);

		mark_inode_dirty(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case EXT2_IOC_GETRSVSZ:
		if (test_opt(inode->i_sb, RESERVATION)
			&& S_ISREG(inode->i_mode)
			&& ei->i_block_alloc_info) {
			rsv_window_size = ei->i_block_alloc_info->rsv_window_node.rsv_goal_size;
			return put_user(rsv_window_size, (int __user *)arg);
		}
		return -ENOTTY;
	case EXT2_IOC_SETRSVSZ: {

		if (!test_opt(inode->i_sb, RESERVATION) ||!S_ISREG(inode->i_mode))
			return -ENOTTY;

		if (!inode_owner_or_capable(&nop_mnt_idmap, inode))
			return -EACCES;

		if (get_user(rsv_window_size, (int __user *)arg))
			return -EFAULT;

		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (rsv_window_size > EXT2_MAX_RESERVE_BLOCKS)
			rsv_window_size = EXT2_MAX_RESERVE_BLOCKS;

		/*
		 * need to allocate reservation structure for this inode
		 * before set the window size
		 */
		/*
		 * XXX What lock should protect the rsv_goal_size?
		 * Accessed in ext2_get_block only.  ext3 uses i_truncate.
		 */
		mutex_lock(&ei->truncate_mutex);
		if (!ei->i_block_alloc_info)
			ext2_init_block_alloc_info(inode);

		if (ei->i_block_alloc_info){
			struct ext2_reserve_window_node *rsv = &ei->i_block_alloc_info->rsv_window_node;
			rsv->rsv_goal_size = rsv_window_size;
		} else {
			ret = -ENOMEM;
		}

		mutex_unlock(&ei->truncate_mutex);
		mnt_drop_write_file(filp);
		return ret;
	}
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long ext2_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case EXT2_IOC32_GETVERSION:
		cmd = EXT2_IOC_GETVERSION;
		break;
	case EXT2_IOC32_SETVERSION:
		cmd = EXT2_IOC_SETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ext2_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
