/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of ACI data structures             */
/* Author and (c) 1999-2025: Amon Ott <ao@rsbac.org> */
/* (some smaller parts copied from fs/namei.c        */
/*  and others)                                      */
/*                                                   */
/* Last modified: 15/Dec/2025                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/quotaops.h>
#include <linux/proc_fs.h>
#include <linux/msdos_fs.h>
#include <linux/iso_fs.h>
#include <linux/nfs_fs.h>
#include <linux/ext2_fs.h>
#include <linux/kthread.h>
#include <linux/coda.h>
#include <linux/initrd.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/srcu.h>
#include <linux/seq_file.h>
#include <linux/magic.h>
#include <linux/dnotify.h>
#include <linux/fsnotify.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/freezer.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/spinlock.h>
#include <linux/fdtable.h>
#include <uapi/linux/wait.h>
#include <uapi/linux/mount.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/fs.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/reg.h>
#include <rsbac/um.h>
#include <rsbac/rkmem.h>
#include <rsbac/gen_lists.h>
#include <rsbac/jail.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include "../../fs/mount.h"
#include "../../fs/internal.h"

#define FUSE_SUPER_MAGIC 0x65735546
#define CEPH_SUPER_MAGIC 0x00c36400

#ifdef CONFIG_RSBAC_MAC
#include <rsbac/mac.h>
#endif

#if defined(CONFIG_RSBAC_RC)
#include <rsbac/rc.h>
#endif

#if defined(CONFIG_RSBAC_AUTH)
#include <rsbac/auth.h>
#endif

#if defined(CONFIG_RSBAC_ACL)
#include <rsbac/acl.h>
#endif

#if defined(CONFIG_RSBAC_JAIL)
rsbac_jail_id_t rsbac_jail_syslog_jail_id = 0;
#endif

#ifdef CONFIG_RSBAC_UM
#include <rsbac/um.h>
#endif

#ifdef CONFIG_RSBAC_UDF
#include <rsbac/udf.h>
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE)
#include <linux/unistd.h>
#include <linux/timer.h>
static u_int auto_interval = CONFIG_RSBAC_AUTO_WRITE * HZ;
#endif				/* CONFIG_RSBAC_AUTO_WRITE */
#if  defined(CONFIG_RSBAC_AUTO_WRITE) \
   || defined(CONFIG_RSBAC_INIT_THREAD) || defined(CONFIG_RSBAC_NO_WRITE)
rsbac_pid_t rsbacd_pid = NULL;
rsbac_pid_t rsbac_mount_pid = NULL;
DEFINE_SPINLOCK(rsbac_mount_lock);
static struct lock_class_key rsbac_mount_lock_class;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE)
static rsbac_boolean_t write_blocked = FALSE;

DEFINE_SPINLOCK(rsbac_write_lock);
static struct lock_class_key rsbac_write_lock_class;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) || defined(CONFIG_RSBAC_INIT_THREAD)
static DECLARE_WAIT_QUEUE_HEAD(rsbacd_wait);
static rsbac_boolean_t rsbacd_awake = FALSE;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
#include <rsbac/network.h>
#endif

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to ACI data.        */

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_initialized);
#endif
rsbac_boolean_t rsbac_initialized = FALSE;

static rsbac_boolean_t rsbac_allow_mounts = FALSE;

static char compiled_modules[80];

rsbac_dev_t rsbac_root_dev;
__u32 rsbac_root_dev_major;
__u32 rsbac_root_dev_minor;
#ifdef CONFIG_RSBAC_INIT_DELAY
struct vfsmount * rsbac_root_vfsmount_p = NULL;
#endif
#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_root_dev);
EXPORT_SYMBOL(rsbac_root_dev_major);
EXPORT_SYMBOL(rsbac_root_dev_minor);
#endif

static struct rsbac_device_list_head_t * device_head_p[BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS)];
static spinlock_t device_list_locks[BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS)];
static struct srcu_struct device_list_srcu[BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS)];
static struct lock_class_key device_list_lock_class;

#ifdef CONFIG_RSBAC_XSTATS
__u64 syscall_count[RSYS_none];
#endif

static struct rsbac_dev_handles_t dev_handles;
static struct rsbac_dev_handles_t dev_major_handles;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_JAIL)
static struct rsbac_ipc_handles_t ipc_handles;
#endif
static struct rsbac_user_handles_t user_handles;
#ifdef CONFIG_RSBAC_RC_UM_PROT
static struct rsbac_group_handles_t group_handles;
#endif
static struct rsbac_process_handles_t process_handles;

#ifdef CONFIG_RSBAC_NET_DEV
static struct rsbac_netdev_handles_t netdev_handles;
#endif
#ifdef CONFIG_RSBAC_NET_OBJ
static rsbac_list_handle_t net_temp_handle;
static struct rsbac_nettemp_handles_t nettemp_handles;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
static struct rsbac_lnetobj_handles_t lnetobj_handles;
static struct rsbac_rnetobj_handles_t rnetobj_handles;
#endif
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
static struct rsbac_gen_netobj_aci_t def_gen_netobj_aci =
    DEFAULT_GEN_NETOBJ_ACI;
#endif
#endif

/* Default ACIs: implemented as variables, might be changeable some time */

/* rsbac root dir items, end of recursive inherit */
static struct rsbac_gen_fd_aci_t def_gen_root_dir_aci =
    DEFAULT_GEN_ROOT_DIR_ACI;
static struct rsbac_gen_fd_aci_t def_gen_fd_aci = DEFAULT_GEN_FD_ACI;

#if defined(CONFIG_RSBAC_MAC)
static struct rsbac_mac_fd_aci_t def_mac_root_dir_aci =
    DEFAULT_MAC_ROOT_DIR_ACI;
static struct rsbac_mac_fd_aci_t def_mac_fd_aci = DEFAULT_MAC_FD_ACI;
#endif
#if defined(CONFIG_RSBAC_RC)
static struct rsbac_rc_fd_aci_t def_rc_root_dir_aci =
    DEFAULT_RC_ROOT_DIR_ACI;
static struct rsbac_rc_fd_aci_t def_rc_fd_aci = DEFAULT_RC_FD_ACI;
#endif
#if defined(CONFIG_RSBAC_UDF)
static struct rsbac_udf_fd_aci_t  def_udf_root_dir_aci  = DEFAULT_UDF_ROOT_DIR_ACI;
#endif

#if defined(CONFIG_RSBAC_PROC)
#include <rsbac/proc_fs.h>

#ifdef CONFIG_RSBAC_XSTATS
static __u64 get_attr_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 set_attr_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 remove_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 get_parent_count = 0;
#endif

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(proc_rsbac_root_p);
#endif
struct proc_dir_entry *proc_rsbac_root_p = NULL;

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(proc_rsbac_backup_p);
#endif
struct proc_dir_entry *proc_rsbac_backup_p = NULL;

#endif				/* PROC */

#ifdef CONFIG_DEVFS_MOUNT
#include <linux/devfs_fs_kernel.h>
#endif

static struct rsbac_mount_list_t * rsbac_mount_list = NULL;

#ifdef CONFIG_RSBAC_MAC
static struct rsbac_mac_process_aci_t mac_init_p_aci =
    DEFAULT_MAC_P_INIT_ACI;
#endif
#ifdef CONFIG_RSBAC_RC
static struct rsbac_rc_process_aci_t rc_kernel_p_aci =
    DEFAULT_RC_P_KERNEL_ACI;
#endif

static __u32 umount_device_in_progress_major = RSBAC_AUTO_DEV_NUM;
static __u32 umount_device_in_progress_minor = RSBAC_AUTO_DEV_NUM;

static struct kmem_cache * device_item_slab = NULL;

#if defined(CONFIG_RSBAC_AUTO_WRITE)
static struct rsbac_delayed_kfree_list_t * delayed_kfree_first = NULL;
static struct rsbac_delayed_kfree_list_t * delayed_kfree_last = NULL;
DEFINE_SPINLOCK(delayed_kfree_lock);
static struct kmem_cache * delayed_kfree_item_slab = NULL;
#ifdef CONFIG_RSBAC_XSTATS
static u_long delayed_kfree_count = 0;
static u_int delayed_kfree_used = 0;
#endif
#endif

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

static struct rsbac_device_list_item_t *lookup_device(__u32 major, __u32 minor, u_int hash);

/************************************************* */
/*               Internal Help functions           */
/************************************************* */

static u_int gen_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
static u_int gen_nr_p_hash_bits = 1;

#if defined(CONFIG_RSBAC_MAC)
static u_int mac_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
static u_int mac_nr_p_hash_bits = 1;
#endif
#if defined(CONFIG_RSBAC_FF)
static u_int ff_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
#endif
#if defined(CONFIG_RSBAC_RC)
static u_int rc_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
static u_int rc_nr_p_hash_bits = 1;
#endif
#if defined(CONFIG_RSBAC_AUTH)
static u_int auth_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
#endif
#if defined(CONFIG_RSBAC_CAP)
static u_int cap_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
#endif
#if defined(CONFIG_RSBAC_JAIL)
static u_int jail_nr_p_hash_bits = 1;
#endif
#if defined(CONFIG_RSBAC_RES)
static u_int res_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
#endif
#if defined(CONFIG_RSBAC_UDF)
static u_int udf_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;

#if defined(CONFIG_RSBAC_UDF_CACHE)
static u_int udf_checked_nr_fd_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
#endif
#endif

static inline u_int device_hash(__u32 minor)
{
  return minor & (BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS) - 1);
}

/* These help functions do NOT handle data consistency protection by */
/* rw-spinlocks! This is done exclusively by non-internal functions! */

/************************************************************************** */
/* Read/Write functions                                                     */

/* This help function protects some filesystems from being written to */
/* and disables writing under some conditions, e.g. in an interrupt */

static rsbac_boolean_t rsbac_type_writable(struct super_block * sb_p)
{
#ifdef CONFIG_RSBAC_NO_WRITE
	return FALSE;
#else
	if (!sb_p || !sb_p->s_dev)
		return FALSE;
	if (   (sb_p->s_magic == SOCKFS_MAGIC)
#ifndef CONFIG_RSBAC_MSDOS_WRITE
	    || (sb_p->s_magic == MSDOS_SUPER_MAGIC)
#endif
	    || (sb_p->s_magic == PIPEFS_MAGIC)
	    || (sb_p->s_magic == TMPFS_MAGIC)
	    || (sb_p->s_magic == ANON_INODE_FS_MAGIC)
	    || (sb_p->s_magic == 0xa10a10a1) /* AIO_RING_MAGIC */
	    || (sb_p->s_magic == BDEVFS_MAGIC)
	    || (sb_p->s_magic == DEVPTS_SUPER_MAGIC)
	    || (sb_p->s_magic == NSFS_MAGIC)
	    || (sb_p->s_magic == PROC_SUPER_MAGIC)
	    || (sb_p->s_magic == DEBUGFS_MAGIC)
	    || (sb_p->s_magic == CGROUP_SUPER_MAGIC)
	    || (sb_p->s_magic == BINFMTFS_MAGIC)
	    || (sb_p->s_magic == SECURITYFS_MAGIC)
	    || (sb_p->s_magic == SELINUX_MAGIC)
	    || (sb_p->s_magic == SYSFS_MAGIC)
	    || (sb_p->s_magic == DMA_BUF_MAGIC)
	    || (sb_p->s_magic == TRACEFS_MAGIC)
	    || (sb_p->s_magic == RAMFS_MAGIC)
	    || (sb_p->s_magic == AUTOFS_SUPER_MAGIC)
	    || (sb_p->s_magic == CGROUP2_SUPER_MAGIC)
	    || (sb_p->s_magic == 0x19800202) /* MQUEUE_MAGIC */
	    || (sb_p->s_magic == BPF_FS_MAGIC)
	    || (sb_p->s_magic == NFS_SUPER_MAGIC)
	    || (sb_p->s_magic == CODA_SUPER_MAGIC)
	    || (sb_p->s_magic == NCP_SUPER_MAGIC)
	    || (sb_p->s_magic == SMB_SUPER_MAGIC)
	    || (sb_p->s_magic == ISOFS_SUPER_MAGIC)
	    || (sb_p->s_magic == OCFS2_SUPER_MAGIC)
	    || (sb_p->s_magic == FUSE_SUPER_MAGIC)
	    || (sb_p->s_magic == CEPH_SUPER_MAGIC)
	    || (sb_p->s_magic == CRAMFS_MAGIC)
	    || (sb_p->s_magic == CRAMFS_MAGIC_WEND)
	    || (sb_p->s_magic == SMACK_MAGIC)
	    || (sb_p->s_magic == HUGETLBFS_MAGIC)
	    || (sb_p->s_magic == SQUASHFS_MAGIC)
	   )
		return FALSE;
	else
		return TRUE;
#endif
}

static rsbac_boolean_t rsbac_device_type_writable(struct rsbac_device_list_item_t *device_p)
{
	if (!device_p || !device_p->vfsmount_p || RSBAC_IS_INVALID_PTR(device_p->vfsmount_p->mnt_sb))
		return FALSE;
	return rsbac_type_writable(device_p->vfsmount_p->mnt_sb);
}

rsbac_boolean_t rsbac_writable(struct super_block * sb_p)
{
#ifdef CONFIG_RSBAC_NO_WRITE
	return FALSE;
#else
	if (!sb_p || !sb_p->s_dev)
		return FALSE;
	if (rsbac_debug_no_write || (sb_p->s_flags & MS_RDONLY)
	    || in_interrupt())
		return FALSE;
	if (!MAJOR(sb_p->s_dev))
		return FALSE;
	return rsbac_type_writable(sb_p);
#endif
}

#ifdef CONFIG_RSBAC_FD_CACHE
static rsbac_boolean_t rsbac_want_cache(struct rsbac_device_list_item_t * device_p)
{
	if (   !rsbac_fd_cache_disable
	    && (   (device_p->major > 1)
		|| (   device_p->vfsmount_p
		    && !RSBAC_IS_INVALID_PTR(device_p->vfsmount_p->mnt_sb)
		    && (
			   (rsbac_fd_cache_fuse && device_p->vfsmount_p->mnt_sb->s_magic == FUSE_SUPER_MAGIC)
			|| (rsbac_fd_cache_ceph && device_p->vfsmount_p->mnt_sb->s_magic == CEPH_SUPER_MAGIC)
		       )
		   )
	       )
	   )
		return TRUE;
	else
		return FALSE;
}
#endif

static int rsbac_set_rsbac_dat_inode(__u32 major, __u32 minor, long dir_fd)
{
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;
	struct fd f;

	f = fdget_pos(dir_fd);
	if (!fd_file(f)) {
		rsbac_printk(KERN_WARNING "rsbac_set_rsbac_dat_inode(): fdget_pos() for dir_fd %lu failed\n",
			     major, minor);
		return -EBADF;
	}

	hash = device_hash(minor);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_set_rsbac_dat_inode(): No entry for device %02u:%02u\n",
			     major, minor);
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	if (device_p->rsbac_dir_inode != fd_file(f)->f_inode->i_ino) {
		rsbac_pr_debug(ds, "rsbac_set_rsbac_dat_inode(): Set rsbac_dir_inode for device %02u:%02u to %llu\n",
			     major, minor, fd_file(f)->f_inode->i_ino);
		device_p->rsbac_dir_inode = fd_file(f)->f_inode->i_ino;
	}
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	fdput_pos(f);
	return 0;
}

/* copy from fs/open.c */
#define WILL_CREATE(flags)      (flags & (O_CREAT | __O_TMPFILE))
#define O_PATH_FLAGS            (O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)
/* end of copy from fs/open.c */

static int rsbac_aci_path_open(struct vfsmount *vfsmount_p, __u32 major, __u32 minor, rsbac_boolean_t create_dir)
{
	long root_fd = 0;
	long dir_fd = 0;
	struct file * f;
	struct open_how how = build_open_how(O_RDONLY, 0);
	struct open_flags op;
	struct path path;
	struct path oldpwd;
	struct dentry *dentry;

	root_fd = get_unused_fd_flags(O_RDONLY);
	if (root_fd < 0)
		return root_fd;

	f = file_open_root_mnt(vfsmount_p, "", O_PATH, 0);
	if (IS_ERR(f)) {
		put_unused_fd(root_fd);
		rsbac_printk(KERN_DEBUG "rsbac_aci_path_open(): opening root dir of device %02u:%02u failed with error %li\n",
			     major, minor, PTR_ERR(f));
		return -RSBAC_ENOTFOUND;
	}

	fd_install(root_fd, f);

	dir_fd = build_open_flags(&how, &op);
	if (dir_fd < 0) {
		close_fd(root_fd);
		rsbac_printk(KERN_WARNING "rsbac_aci_path_open(): build_open_flags() for %s dir on device %02u:%02u failed with error %li\n",
			     RSBAC_ACI_PATH, major, minor, dir_fd);
		return -RSBAC_ENOTFOUND;
	}
	dir_fd = get_unused_fd_flags(how.flags);
	if (dir_fd >= 0) {
		struct file * f2;
		struct filename *name = getname_kernel(RSBAC_ACI_PATH);

		f2 = do_filp_open(root_fd, name, &op);
		putname(name);
		if (!IS_ERR(f2)) {
			fsnotify_open(f2);
			fd_install(dir_fd, f2);
			close_fd(root_fd);
			rsbac_set_rsbac_dat_inode(major, minor, dir_fd);
			return dir_fd;
		}
		put_unused_fd(dir_fd);
	}
	if (!create_dir) {
		close_fd(root_fd);
#ifdef CONFIG_RSBAC_DEBUG
		if (rsbac_debug_ds) {
			rsbac_pr_debug(ds, "%s not found on device %02u:%02u, no create!\n",
				       RSBAC_ACI_PATH, MAJOR(vfsmount_p->mnt_sb->s_dev), MINOR(vfsmount_p->mnt_sb->s_dev));
		}
#endif
		return -RSBAC_ENOTFOUND;
	}
	if (!rsbac_writable(vfsmount_p->mnt_sb)) {
		rsbac_pr_debug(write, "called for non-writable device\n");
		close_fd(root_fd);
		return -RSBAC_ENOTWRITABLE;
	}
	get_fs_pwd(current->fs, &oldpwd);
	set_fs_pwd(current->fs, &f->f_path);
	dentry = start_creating_path(AT_FDCWD, RSBAC_ACI_PATH, &path, LOOKUP_DIRECTORY);
	set_fs_pwd(current->fs, &oldpwd);
	path_put(&oldpwd);
	if (IS_ERR(dentry)) {
		close_fd(root_fd);
		rsbac_printk(KERN_WARNING "rsbac_aci_path_open(): creating %s dir on device %02u:%02u failed with error %li\n",
			     RSBAC_ACI_PATH, major, minor, PTR_ERR(dentry));
		return -RSBAC_ENOTFOUND;
	}
	dentry = vfs_mkdir(mnt_idmap(vfsmount_p), path.dentry->d_inode, dentry, 0);
	end_creating_path(&path, dentry);
	if (IS_ERR(dentry)) {
		close_fd(root_fd);
		rsbac_printk(KERN_WARNING "rsbac_aci_path_open(): creating %s dir on device %02u:%02u failed with error %li\n",
				RSBAC_ACI_PATH, major, minor, dir_fd);
		return -RSBAC_ENOTFOUND;
	}

	dir_fd = build_open_flags(&how, &op);
	if (dir_fd < 0) {
		close_fd(root_fd);
		rsbac_printk(KERN_WARNING "rsbac_aci_path_open(): creating %s dir on device %02u:%02u failed with error %li\n",
			     RSBAC_ACI_PATH, major, minor, dir_fd);
		return -RSBAC_ENOTFOUND;
	}
	dir_fd = get_unused_fd_flags(how.flags);
	if (dir_fd >= 0) {
		struct file * f2;
		struct filename *name = getname_kernel(RSBAC_ACI_PATH);

		f2 = do_filp_open(root_fd, name, &op);
		putname(name);
		if (!IS_ERR(f2)) {
			fsnotify_open(f2);
			fd_install(dir_fd, f2);
			close_fd(root_fd);
			rsbac_set_rsbac_dat_inode(major, minor, dir_fd);
			return dir_fd;
		}
		put_unused_fd(dir_fd);
	}
	rsbac_printk(KERN_WARNING "rsbac_aci_path_open(): opening %s dir on device %02u:%02u after mkdir failed with error %li\n",
		     RSBAC_ACI_PATH, major, minor, dir_fd);
	return -RSBAC_ENOTFOUND;
}

static int rsbac_aci_path_close(unsigned int fd) {
	return close_fd(fd);
}

/************************************************************************** */
/* The lookup functions return NULL, if the item is not found, and a        */
/* pointer to the item otherwise.                                           */

/* First, a lookup for the device list item                                 */

static struct rsbac_device_list_item_t *lookup_device(__u32 major, __u32 minor, u_int hash)
{
	struct rsbac_device_list_head_t *head_p = srcu_dereference(device_head_p[hash], &device_list_srcu[hash]);
	struct rsbac_device_list_item_t *curr = srcu_dereference(head_p->curr, &device_list_srcu[hash]);

	/* if there is no current item or it is not the right one, search... */
	if (!(   curr
	      && (curr->minor == minor)
	      && (curr->major == major)
	   ) ) {
		curr = srcu_dereference(head_p->head, &device_list_srcu[hash]);
		while (   curr
		       && (   (curr->minor != minor)
			   || (curr->major != major)
			  )
		      ) {
			curr = srcu_dereference(curr->next, &device_list_srcu[hash]);
		}
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_device_list_item_t *lookup_device_locked(__u32 major, __u32 minor, u_int hash)
{
	struct rsbac_device_list_item_t *curr = device_head_p[hash]->curr;

	/* if there is no current item or it is not the right one, search... */
	if (!(   curr
	      && (curr->minor == minor)
	      && (curr->major == major)
	   ) ) {
		curr = device_head_p[hash]->head;
		while (   curr
		       && (   (curr->minor != minor)
			   || (curr->major != major)
			  )
		      ) {
			curr = curr->next;
		}
		if (curr)
			device_head_p[hash]->curr = curr;
	}
	/* it is the current item -> return it */
	return curr;
}

static int dev_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	result = memcmp(&i_desc1->major,
			&i_desc2->major, sizeof(i_desc1->major));
	if (result)
		return result;
	return memcmp(&i_desc1->minor,
		      &i_desc2->minor, sizeof(i_desc1->minor));
}

#ifdef CONFIG_RSBAC_RC
static int dev_major_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	return memcmp(&i_desc1->major,
		      &i_desc2->major, sizeof(i_desc1->major));
}
#endif

#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_JAIL)
static int ipc_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_ipc_t *i_desc1 = desc1;
	struct rsbac_ipc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->id.id_nr,
			&i_desc2->id.id_nr,
			sizeof(i_desc1->id.id_nr));
	if (result)
		return result;
	else
		return memcmp(&i_desc1->type,
				&i_desc2->type, sizeof(i_desc1->type));
}
#endif

#ifdef CONFIG_RSBAC_NET_DEV
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG) || defined(CONFIG_RSBAC_RC)
static int netdev_compare(void *desc1, void *desc2)
{
	return strncmp(desc1, desc2, RSBAC_IFNAMSIZ);
}
#endif
#endif

/************************************************************************** */
/* Convert functions                                                        */

static int gen_fd_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_gen_fd_aci_t *new_aci = new_data;
	struct rsbac_gen_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->log_array_low = old_aci->log_array_low;
	new_aci->log_array_high = old_aci->log_array_high;
	new_aci->log_program_based = old_aci->log_program_based;
	new_aci->symlink_add_remote_ip = old_aci->symlink_add_remote_ip;
	new_aci->symlink_add_uid = old_aci->symlink_add_uid;
	new_aci->symlink_add_mac_level = old_aci->symlink_add_mac_level;
	new_aci->symlink_add_rc_role = old_aci->symlink_add_rc_role;
	new_aci->allow_write_exec = old_aci->allow_write_exec;
	new_aci->fake_root_uid = old_aci->fake_root_uid;
	new_aci->auid_exempt = old_aci->auid_exempt;
	new_aci->vset = RSBAC_UM_VIRTUAL_KEEP;
	return 0;
}

static int gen_fd_old_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_gen_fd_aci_t *new_aci = new_data;
	struct rsbac_gen_fd_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->log_array_low = old_aci->log_array_low;
	new_aci->log_array_high = old_aci->log_array_high;
	new_aci->log_program_based = old_aci->log_program_based;
	new_aci->symlink_add_remote_ip = 0;
	new_aci->symlink_add_uid = old_aci->symlink_add_uid;
	new_aci->symlink_add_mac_level = old_aci->symlink_add_mac_level;
	new_aci->symlink_add_rc_role = old_aci->symlink_add_rc_role;
	new_aci->allow_write_exec = old_aci->allow_write_exec;
	new_aci->fake_root_uid = old_aci->fake_root_uid;
	new_aci->auid_exempt = old_aci->auid_exempt;
	new_aci->vset = RSBAC_UM_VIRTUAL_KEEP;
	return 0;
}

static rsbac_list_conv_function_t *gen_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_FD_OLD_ACI_VERSION:
		return gen_fd_conv;
	case RSBAC_GEN_FD_OLD_OLD_ACI_VERSION:
		return gen_fd_old_conv;
	default:
		return NULL;
	}
}

static int gen_dev_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_old_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(struct rsbac_gen_dev_aci_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *gen_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_DEV_OLD_ACI_VERSION:
		return gen_dev_conv;
	default:
		return NULL;
	}
}

static int gen_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_gen_user_aci_t));
	return 0;
}

static rsbac_list_conv_function_t *gen_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_USER_OLD_ACI_VERSION:
		return gen_user_conv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_MAC
static int mac_old_fd_conv(void *old_desc,
			   void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = old_aci->mac_prop_trusted;
	new_aci->mac_file_flags = old_aci->mac_file_flags;
	return 0;
}

static int mac_old_old_fd_conv(void *old_desc,
			       void *old_data,
			       void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = FALSE;
	if (old_aci->mac_shared)
		new_aci->mac_file_flags = MAC_write_up;
	else
		new_aci->mac_file_flags = 0;
	return 0;
}

static int mac_old_old_old_fd_conv(void *old_desc,
				   void *old_data,
				   void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = FALSE;
	new_aci->mac_file_flags = 0;
	return 0;
}

static rsbac_list_conv_function_t *mac_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_FD_OLD_ACI_VERSION:
		return mac_old_fd_conv;
	case RSBAC_MAC_FD_OLD_OLD_ACI_VERSION:
		return mac_old_old_fd_conv;
	case RSBAC_MAC_FD_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_old_fd_conv;
	default:
		return NULL;
	}
}

static int mac_dev_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_old_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(struct rsbac_mac_dev_aci_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *mac_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_DEV_OLD_ACI_VERSION:
		return mac_dev_conv;
	default:
		return NULL;
	}
}

static int mac_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_mac_user_aci_t));
	return 0;
}

static int mac_old_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = old_aci->min_access_appr;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = old_aci->mac_min_categories;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	if (old_aci->mac_allow_auto)
		new_aci->mac_user_flags |= MAC_allow_auto;
	return 0;
}

static int mac_old_old_user_conv(void *old_desc,
				 void *old_data,
				 void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = old_aci->min_access_appr;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = old_aci->mac_min_categories;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	return 0;
}

static int mac_old_old_old_user_conv(void *old_desc,
				     void *old_data,
				     void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_old_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = SL_unclassified;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	return 0;
}

static rsbac_list_conv_function_t *mac_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_USER_OLD_ACI_VERSION:
		return mac_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_ACI_VERSION:
		return mac_old_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_old_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_FF
static int ff_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *ff_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_FF_USER_OLD_ACI_VERSION:
		return ff_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_RC
static int rc_dev_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_old_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(rsbac_rc_type_id_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *rc_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RC_DEV_OLD_ACI_VERSION:
		return rc_dev_conv;
	default:
		return NULL;
	}
}

static int rc_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_rc_user_aci_t));
	return 0;
}

static int rc_user_old_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_rc_user_aci_t *new_aci = new_data;
	rsbac_rc_role_id_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->rc_role = *old_aci;
	new_aci->rc_type = RSBAC_RC_GENERAL_TYPE;
	return 0;
}

static rsbac_list_conv_function_t *rc_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RC_USER_OLD_ACI_VERSION:
		return rc_user_conv;
	case RSBAC_RC_USER_OLD_OLD_ACI_VERSION:
		return rc_user_old_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_AUTH
static int auth_old_fd_conv(void *old_desc,
			    void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_auth_fd_aci_t *new_aci = new_data;
	struct rsbac_auth_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->auth_may_setuid = old_aci->auth_may_setuid;
	new_aci->auth_may_set_cap = old_aci->auth_may_set_cap;
	new_aci->auth_learn = FALSE;
	return 0;
}

static rsbac_list_conv_function_t *auth_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_FD_OLD_ACI_VERSION:
		return auth_old_fd_conv;
	default:
		return NULL;
	}
}

static int auth_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *auth_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_USER_OLD_ACI_VERSION:
		return auth_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_CAP
static int cap_old_fd_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_cap_fd_aci_t *new_aci = new_data;
	struct rsbac_cap_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_old_inode_nr_t));
	new_aci->min_caps = old_aci->min_caps.cap[0] | ((__u64) old_aci->min_caps.cap[1]) << 32;
	new_aci->max_caps = old_aci->max_caps.cap[0] | ((__u64) old_aci->max_caps.cap[1]) << 32;
	new_aci->cap_ld_env = old_aci->cap_ld_env;
	return 0;
}

static rsbac_list_conv_function_t *cap_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_CAP_FD_OLD_ACI_VERSION:
			return cap_old_fd_conv;
		default:
			return NULL;
	}
}

static int cap_old_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	struct rsbac_cap_user_aci_t *new_aci = new_data;
	struct rsbac_cap_user_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_uid_t));
	new_aci->cap_role = old_aci->cap_role;
	new_aci->min_caps = old_aci->min_caps.cap[0] | ((__u64) old_aci->min_caps.cap[1]) << 32;
	new_aci->max_caps = old_aci->max_caps.cap[0] | ((__u64) old_aci->max_caps.cap[1]) << 32;
	new_aci->cap_ld_env = old_aci->cap_ld_env;
	return 0;
}

static rsbac_list_conv_function_t *cap_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_CAP_USER_OLD_ACI_VERSION:
			return cap_old_user_conv;
		default:
			return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_JAIL
static int jail_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *jail_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_JAIL_USER_OLD_ACI_VERSION:
		return jail_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_RES
static int res_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_res_user_aci_t));
	return 0;
}

static rsbac_list_conv_function_t *res_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RES_USER_OLD_ACI_VERSION:
		return res_user_conv;
	default:
		return NULL;
	}
}
#endif


#ifdef CONFIG_RSBAC_NET_OBJ
static int net_temp_old_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_net_temp_data_t *new_aci = new_data;
	struct rsbac_net_temp_old_data_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	new_aci->address_family = old_aci->address_family;
	new_aci->type = old_aci->type;
	new_aci->protocol = old_aci->protocol;
	memcpy(new_aci->netdev, old_aci->netdev, sizeof(rsbac_netdev_id_t));
	memcpy(new_aci->name, old_aci->name, sizeof(new_aci->name));
	switch(new_aci->address_family) {
		case AF_INET:
			new_aci->address.inet.nr_addr = 1;
			new_aci->address.inet.addr[0] = *((__u32 *) old_aci->address);
			new_aci->address.inet.valid_bits[0] = old_aci->valid_len;
			if((old_aci->min_port == 0) && (old_aci->max_port == RSBAC_NET_MAX_PORT))
				new_aci->ports.nr_ports = 0;
			else {
				new_aci->ports.nr_ports = 1;
				new_aci->ports.ports[0].min = old_aci->min_port;
				new_aci->ports.ports[0].max = old_aci->max_port;
			}
			break;
		default:
			memcpy(new_aci->address.other.addr, old_aci->address, sizeof(old_aci->address));
			new_aci->address.other.valid_len = old_aci->valid_len;
			new_aci->ports.nr_ports = 0;
			break;
	}
	return 0;
}


static rsbac_list_conv_function_t *net_temp_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_NET_TEMP_OLD_VERSION:
			return net_temp_old_conv;
		default:
			return NULL;
	}
}
#endif

/************************************************************************** */
/* The add_item() functions add an item to the list, set head.curr to it,   */
/* and return a pointer to the item.                                        */
/* These functions will NOT check, if there is already an item under the    */
/* same ID! If this happens, the lookup functions will return the old item! */
/* All list manipulation must be protected by rw-spinlocks to prevent       */
/* inconsistency and undefined behaviour in other concurrent functions.     */

/* register_fd_lists() */
/* register fd lists for device */

static int register_fd_lists(struct rsbac_device_list_item_t *device_p,
			     __u32 major, __u32 minor)
{
	char *name;
	int err = 0;
	int tmperr;
	struct rsbac_list_info_t *info_p;
	u_int tmp_flags;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;
	name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
	if (!name)
		return -RSBAC_ENOMEM;
	info_p = rsbac_kmalloc(sizeof(*info_p));
	if (!info_p) {
		rsbac_kfree(name);
		return -RSBAC_ENOMEM;
	}
	if (rsbac_device_type_writable(device_p)) {
		tmp_flags = RSBAC_LIST_PERSIST;
		device_p->persist = TRUE;
	} else {
		tmp_flags = 0;
		device_p->persist = FALSE;
	}

	/* register general lists */
	{
		info_p->version = RSBAC_GEN_FD_ACI_VERSION;
		info_p->key = RSBAC_GEN_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_gen_fd_aci_t);
		info_p->max_age = 0;
		gen_nr_fd_hash_bits = RSBAC_GEN_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.gen,
					     info_p,
					     tmp_flags |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     gen_fd_get_conv,
					     &def_gen_fd_aci,
					     RSBAC_GEN_FD_NAME,
					     major, minor,
					     gen_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_GEN_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering general list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_GEN_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}

#if defined(CONFIG_RSBAC_MAC)
	{
		/* register MAC lists */
		info_p->version = RSBAC_MAC_FD_ACI_VERSION;
		info_p->key = RSBAC_MAC_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_mac_fd_aci_t);
		info_p->max_age = 0;
		mac_nr_fd_hash_bits = RSBAC_MAC_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.mac,
					     info_p,
					     tmp_flags | RSBAC_LIST_OWN_SLAB |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     mac_fd_get_conv,
					     &def_mac_fd_aci,
					     RSBAC_MAC_FD_NAME,
					     major, minor,
					     mac_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_MAC_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering MAC list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_MAC_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_FF)
	{
		rsbac_ff_flags_t def_ff_fd_aci = RSBAC_FF_DEF;

		info_p->version = RSBAC_FF_FD_ACI_VERSION;
		info_p->key = RSBAC_FF_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size = sizeof(rsbac_ff_flags_t);
		info_p->max_age = 0;
		ff_nr_fd_hash_bits = RSBAC_FF_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.ff,
					     info_p,
					     tmp_flags | RSBAC_LIST_OWN_SLAB |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_ff_fd_aci,
					     RSBAC_FF_FD_NAME, major, minor,
					     ff_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_FF_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering FF list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_FF_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_RC)
	{
		info_p->version = RSBAC_RC_FD_ACI_VERSION;
		info_p->key = RSBAC_RC_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_rc_fd_aci_t);
		info_p->max_age = 0;
		rc_nr_fd_hash_bits = RSBAC_RC_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.rc,
					     info_p,
					     tmp_flags | RSBAC_LIST_OWN_SLAB |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_rc_fd_aci,
					     RSBAC_RC_FD_NAME, major, minor,
					     rc_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_RC_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering RC list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_RC_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_AUTH)
	{
		struct rsbac_auth_fd_aci_t def_auth_fd_aci =
		    DEFAULT_AUTH_FD_ACI;

		info_p->version = RSBAC_AUTH_FD_ACI_VERSION;
		info_p->key = RSBAC_AUTH_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_auth_fd_aci_t);
		info_p->max_age = 0;
		auth_nr_fd_hash_bits = RSBAC_AUTH_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.auth,
					     info_p,
					     tmp_flags |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     auth_fd_get_conv,
					     &def_auth_fd_aci,
					     RSBAC_AUTH_FD_NAME, major, minor,
					     auth_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_AUTH_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering AUTH list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_AUTH_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_fd_aci_t def_cap_fd_aci = DEFAULT_CAP_FD_ACI;

		info_p->version = RSBAC_CAP_FD_ACI_VERSION;
		info_p->key = RSBAC_CAP_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_cap_fd_aci_t);
		info_p->max_age = 0;
		cap_nr_fd_hash_bits = RSBAC_CAP_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.cap,
					     info_p,
					     tmp_flags |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     cap_fd_get_conv, 
					     &def_cap_fd_aci,
					     RSBAC_CAP_FD_NAME, major, minor,
					     cap_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     RSBAC_CAP_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering CAP list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_CAP_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_RES)
	{
		struct rsbac_list_lol_info_t *list_lol_info_p;
		rsbac_res_limit_t def_value;

		list_lol_info_p = rsbac_kmalloc_unlocked(sizeof(*list_lol_info_p));
		if (!list_lol_info_p) {
			err = -ENOMEM;
			goto skip;
		}
		list_lol_info_p->version = RSBAC_RES_FD_ACI_VERSION;
		list_lol_info_p->key = RSBAC_RES_FD_ACI_KEY;
		list_lol_info_p->desc_size = sizeof(rsbac_inode_nr_t);
		list_lol_info_p->data_size = 0;
		list_lol_info_p->subdesc_size = sizeof(rsbac_res_desc_t);
		list_lol_info_p->subdata_size = sizeof(rsbac_res_limit_t);
		list_lol_info_p->max_age = 0;
		res_nr_fd_hash_bits = RSBAC_RES_NR_FD_LIST_HASH_BITS;
		def_value = 0;

		tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				&device_p->handles.res_min,
				list_lol_info_p,
				tmp_flags | \
				RSBAC_LIST_OWN_SLAB | \
				RSBAC_LIST_DEF_DATA | \
				RSBAC_LIST_DEF_SUBDATA | \
					RSBAC_LIST_AUTO_HASH_RESIZE,
				NULL, /* compare */
				NULL, /* subcompare */
				NULL, NULL, /* get_conv */
				NULL, &def_value, /* def data */
				RSBAC_RES_FD_MIN_NAME,
				device_p->major, device_p->minor,
				res_nr_fd_hash_bits,
				rsbac_list_hash_fd,
				NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering RES list of lists %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_RES_FD_MIN_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		} else {
			if (rsbac_list_lol_count(device_p->handles.res_min) == 0) {
				rsbac_list_handle_t old_res_handle;

#if 0
				rsbac_printk(KERN_INFO "register_fd_lists(): RES list of lists %s for device %02u:%02u is empty, try to fill from old RES list %s!\n",
					     RSBAC_RES_FD_MIN_NAME,
					     major, minor,
					     RSBAC_RES_OLD_FD_NAME);
#endif
				info_p->version = RSBAC_RES_FD_ACI_VERSION;
				info_p->key = RSBAC_RES_FD_ACI_KEY;
				info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
				info_p->data_size = sizeof(struct rsbac_res_old_fd_aci_t);
				info_p->max_age = 0;
				tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
								&old_res_handle,
								info_p,
								tmp_flags |
								RSBAC_LIST_AUTO_HASH_RESIZE,
								NULL,
								NULL, NULL,
								RSBAC_RES_OLD_FD_NAME, major, minor,
								res_nr_fd_hash_bits,
								tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
								NULL);
				if (tmperr) {
					char *tmp;

					tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
					if (tmp) {
						rsbac_printk(KERN_WARNING "register_fd_lists(): registering old RES list %s for device %02u:%02u failed with error %s!\n",
							     RSBAC_RES_OLD_FD_NAME,
							     major, minor,
							     get_error_name(tmp,
									    tmperr));
						rsbac_kfree(tmp);
					}
				} else {
					char * array_p;
					rsbac_time_t * ttl_p;
					long item_count;

					item_count = rsbac_list_get_all_items_ttl(old_res_handle, (void **) &array_p, &ttl_p);
					if (item_count > 0) {
						char *tmp = array_p;
						int size = rsbac_list_get_item_size(old_res_handle);
						rsbac_inode_nr_t inode_nr;
						int i;
						rsbac_res_desc_t res_num;
						rsbac_res_limit_t res_value;
						int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);

						for (i = 0; i < item_count; i++) {
							if (tmp_flags)
								inode_nr = *((rsbac_old_inode_nr_t *) tmp);
							else
								inode_nr = *((rsbac_inode_nr_t *) tmp);
							for(res_num = 0; res_num <= maxval ; res_num++) {
								res_value = ( (struct rsbac_res_old_fd_aci_t *) (tmp + info_p->desc_size) )->res_min[res_num];
								if (res_value != 0)
									rsbac_ta_list_lol_subadd_ttl(0,
												device_p->handles.res_min, ttl_p[i],
												&inode_nr, &res_num,
												&res_value);
							}
							tmp += size;
						}
						rsbac_kfree(array_p);
						rsbac_kfree(ttl_p);
					}
					rsbac_list_detach(&old_res_handle, RSBAC_RES_FD_ACI_KEY);
					if (item_count > 0)
						rsbac_printk(KERN_DEBUG "register_fd_lists(): RES list of lists %s got %lu items from old RES list %s!\n",
							     RSBAC_RES_FD_MIN_NAME,
							     item_count,
							     RSBAC_RES_OLD_FD_NAME);
				}
			}
		}

		tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				&device_p->handles.res_max,
				list_lol_info_p,
				tmp_flags | \
				RSBAC_LIST_OWN_SLAB | \
				RSBAC_LIST_DEF_DATA | \
				RSBAC_LIST_DEF_SUBDATA | \
					RSBAC_LIST_AUTO_HASH_RESIZE,
				NULL, /* compare */
				NULL, /* subcompare */
				NULL, NULL, /* get_conv */
				NULL, &def_value, /* def data */
				RSBAC_RES_FD_MAX_NAME,
				device_p->major, device_p->minor,
				res_nr_fd_hash_bits,
				rsbac_list_hash_fd,
				NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering RES list of lists %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_RES_FD_MAX_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		} else {
			if (rsbac_list_lol_count(device_p->handles.res_max) == 0) {
				rsbac_list_handle_t old_res_handle;

#if 0
				rsbac_printk(KERN_INFO "register_fd_lists(): RES list of lists %s for device %02u:%02u is empty, try to fill from old RES list %s!\n",
					     RSBAC_RES_FD_MAX_NAME,
					     major, minor,
					     RSBAC_RES_OLD_FD_NAME);
#endif
				info_p->version = RSBAC_RES_FD_ACI_VERSION;
				info_p->key = RSBAC_RES_FD_ACI_KEY;
				info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
				info_p->data_size = sizeof(struct rsbac_res_old_fd_aci_t);
				info_p->max_age = 0;
				tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
								&old_res_handle,
								info_p,
								tmp_flags |
								RSBAC_LIST_AUTO_HASH_RESIZE,
								NULL,
								NULL, NULL,
								RSBAC_RES_OLD_FD_NAME, major, minor,
								res_nr_fd_hash_bits,
								tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
								NULL);
				if (tmperr) {
					char *tmp;

					tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
					if (tmp) {
						rsbac_printk(KERN_WARNING "register_fd_lists(): registering old RES list %s for device %02u:%02u failed with error %s!\n",
							     RSBAC_RES_OLD_FD_NAME,
							     major, minor,
							     get_error_name(tmp,
									    tmperr));
						rsbac_kfree(tmp);
					}
				} else {
					char * array_p;
					rsbac_time_t * ttl_p;
					long item_count;

					item_count = rsbac_list_get_all_items_ttl(old_res_handle, (void **) &array_p, &ttl_p);
					if (item_count > 0) {
						char *tmp = array_p;
						int size = rsbac_list_get_item_size(old_res_handle);
						rsbac_inode_nr_t inode_nr;
						int i;
						rsbac_res_desc_t res_num;
						rsbac_res_limit_t res_value;
						int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);

						for (i = 0; i < item_count; i++) {
							if (tmp_flags)
								inode_nr = *((rsbac_old_inode_nr_t *) tmp);
							else
								inode_nr = *((rsbac_inode_nr_t *) tmp);
							for(res_num = 0; res_num <= maxval ; res_num++) {
								res_value = ( (struct rsbac_res_old_fd_aci_t *) (tmp + info_p->desc_size) )->res_max[res_num];
								if (res_value != 0)
									rsbac_ta_list_lol_subadd_ttl(0,
												device_p->handles.res_max, ttl_p[i],
												&inode_nr, &res_num,
												&res_value);
							}
							tmp += size;
						}
						rsbac_kfree(array_p);
						rsbac_kfree(ttl_p);
					}
					rsbac_list_detach(&old_res_handle, RSBAC_RES_FD_ACI_KEY);
					if (item_count > 0)
						rsbac_printk(KERN_DEBUG "register_fd_lists(): RES list of lists %s got %lu items from old RES list %s!\n",
							     RSBAC_RES_FD_MAX_NAME,
							     item_count,
							     RSBAC_RES_OLD_FD_NAME);
				}
			}
		}
		rsbac_kfree(list_lol_info_p);
	}
skip:
#endif

#if defined(CONFIG_RSBAC_UDF)
	{
		struct rsbac_udf_fd_aci_t def_udf_fd_aci =
		    DEFAULT_UDF_FD_ACI;
		/* register UDF lists */
		info_p->version = RSBAC_UDF_FD_ACI_VERSION;
		info_p->key = RSBAC_UDF_FD_ACI_KEY;
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_udf_fd_aci_t);
		info_p->max_age = 0;
		udf_nr_fd_hash_bits = RSBAC_UDF_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.udf,
					     info_p,
					     tmp_flags |
					     RSBAC_LIST_DEF_DATA |
					     RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL,
					     &def_udf_fd_aci,
					     RSBAC_UDF_FD_NAME, major, minor,
					     udf_nr_fd_hash_bits,
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
					     NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering UDF list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_UDF_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#if defined(CONFIG_RSBAC_UDF_CACHE)
	{
		rsbac_udf_checked_t def_udf_checked_fd_aci =
		    DEFAULT_UDF_FD_CHECKED;

		info_p->version = RSBAC_UDF_CHECKED_FD_ACI_VERSION;
		info_p->key = RSBAC_UDF_FD_ACI_KEY;
#ifdef CONFIG_RSBAC_UDF_PERSIST
		info_p->desc_size = tmp_flags ? sizeof(rsbac_old_inode_nr_t) : sizeof(rsbac_inode_nr_t);
#else
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
#endif
		info_p->data_size = sizeof(rsbac_udf_checked_t);
		info_p->max_age = 0;
		udf_checked_nr_fd_hash_bits = RSBAC_UDF_CHECKED_NR_FD_LIST_HASH_BITS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.udfc,
					     info_p,
#ifdef CONFIG_RSBAC_UDF_PERSIST
					     tmp_flags |
#endif
					     RSBAC_LIST_DEF_DATA | (major ? RSBAC_LIST_OWN_SLAB : 0) |
					     RSBAC_LIST_AUTO_HASH_RESIZE |
					     RSBAC_LIST_NO_MAX,
					     NULL,
					     NULL,
					     &def_udf_checked_fd_aci,
					     RSBAC_UDF_CHECKED_FD_NAME, major, minor,
					     udf_checked_nr_fd_hash_bits,
#ifdef CONFIG_RSBAC_UDF_PERSIST
					     tmp_flags ? rsbac_list_hash_old_fd : rsbac_list_hash_fd,
#else
					     rsbac_list_hash_fd,
#endif
					     NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering UDF checked list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_UDF_CHECKED_FD_NAME,
					     major, minor,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif
#endif

	rsbac_kfree(name);
	rsbac_kfree(info_p);
	return err;
}

/* aci_detach_fd_lists() */
/* detach from fd lists for device */

static int aci_detach_fd_lists(struct rsbac_device_list_item_t *device_p)
{
	int err = 0;
	int tmperr;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	/* detach all general lists */
	tmperr = rsbac_list_detach(&device_p->handles.gen,
					   RSBAC_GEN_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from general list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_GEN_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}

#if defined(CONFIG_RSBAC_MAC)
	/* detach all MAC lists */
	tmperr = rsbac_list_detach(&device_p->handles.mac,
				   RSBAC_MAC_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from MAC list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_MAC_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_FF)
	/* detach all FF lists */
	tmperr = rsbac_list_detach(&device_p->handles.ff,
				   RSBAC_FF_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from FF list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_FF_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_RC)
	/* detach all RC lists */
	tmperr = rsbac_list_detach(&device_p->handles.rc,
				   RSBAC_RC_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from RC list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_RC_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_AUTH)
	/* detach all AUTH lists */
	tmperr = rsbac_list_detach(&device_p->handles.auth,
			      RSBAC_AUTH_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from AUTH list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_CAP)
	/* detach all CAP lists */
	tmperr = rsbac_list_detach(&device_p->handles.cap,
				   RSBAC_CAP_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from CAP list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_CAP_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_RES)
	/* detach all RES lists */
	tmperr = rsbac_list_lol_detach(&device_p->handles.res_min,
				   RSBAC_RES_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from RES list of lists %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_RES_FD_MIN_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
	tmperr = rsbac_list_lol_detach(&device_p->handles.res_max,
				   RSBAC_RES_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from RES list of lists %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_RES_FD_MAX_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_UDF)
	/* detach all UDF lists */
	tmperr = rsbac_list_detach(&device_p->handles.udf,
				   RSBAC_UDF_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from UDF list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_UDF_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#if defined(CONFIG_RSBAC_UDF_CACHE)
	/* detach all UDF checked lists */
	tmperr = rsbac_list_detach(&device_p->handles.udfc,
				      RSBAC_UDF_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from UDF checked list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_UDF_CHECKED_FD_NAME,
				     device_p->major, device_p->minor,
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif
#endif

	return err;
}

static void registration_error(int err, char *listname)
{
	if (err < 0) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): Registering %s list failed with error %s\n",
				     listname, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
}

#ifdef CONFIG_RSBAC_FD_CACHE
static int register_fd_cache_lists(struct rsbac_device_list_item_t *device_p)
{
	int err = 0;
	struct rsbac_list_lol_info_t *list_info_p;
	char * tmp;

	if (device_p->fd_cache_handle[SW_GEN]) {
		rsbac_printk(KERN_WARNING "register_fd_cache_lists(): GEN list for device %02u:%02u already registered, refusing device!\n",
				device_p->major, device_p->minor);
		return -RSBAC_EINVALIDDEV;
	}

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
	if (!tmp) {
		rsbac_kfree(list_info_p);
		return -ENOMEM;
	}
	rsbac_pr_debug(fdcache, "registering FD Cache lists for device %02u:%02u\n",
			device_p->major, device_p->minor);
	list_info_p->version = RSBAC_FD_CACHE_VERSION;
	list_info_p->key = RSBAC_FD_CACHE_KEY;
	list_info_p->desc_size = sizeof(rsbac_inode_nr_t);
	list_info_p->data_size = 0;
	list_info_p->subdesc_size = sizeof(rsbac_enum_t);
	list_info_p->subdata_size =
	    sizeof(union rsbac_attribute_value_cache_t);
	list_info_p->max_age = 0;

#ifdef CONFIG_RSBAC_MPROTECT
	sprintf(tmp, "%sGEN", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &(device_p->fd_cache_handle[SW_GEN]), list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  device_p->major, device_p->minor,
				  RSBAC_LIST_MIN_MAX_HASH_BITS,
				  rsbac_list_hash_fd,
				  NULL);
	if (err) {
		char *tmp2;

		tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp2) {
			rsbac_printk(KERN_WARNING "register_fd_cache_lists(): registering GEN list %s for device %02u:%02u failed with error %s!\n",
				     tmp,
				     device_p->major, device_p->minor,
				     get_error_name(tmp2, err));
			rsbac_kfree(tmp2);
		}
	} else
		rsbac_list_lol_max_items(device_p->fd_cache_handle[SW_GEN],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif

#if defined(CONFIG_RSBAC_MAC) && defined(CONFIG_RSBAC_MAC_DEF_INHERIT)
	sprintf(tmp, "%sMAC", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &(device_p->fd_cache_handle[SW_MAC]), list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  device_p->major, device_p->minor,
				  RSBAC_LIST_MIN_MAX_HASH_BITS,
				  rsbac_list_hash_fd,
				  NULL);
	if (err) {
		char *tmp2;

		tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp2) {
			rsbac_printk(KERN_WARNING "register_fd_cache_lists(): registering MAC list %s for device %02u:%02u failed with error %s!\n",
				     tmp,
				     device_p->major, device_p->minor,
				     get_error_name(tmp2, err));
			rsbac_kfree(tmp2);
		}
	} else
		rsbac_list_lol_max_items(device_p->fd_cache_handle[SW_MAC],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_FF)
	sprintf(tmp, "%sFF", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &(device_p->fd_cache_handle[SW_FF]), list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  device_p->major, device_p->minor,
				  RSBAC_LIST_MIN_MAX_HASH_BITS,
				  rsbac_list_hash_fd,
				  NULL);
	if (err) {
		char *tmp2;

		tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp2) {
			rsbac_printk(KERN_WARNING "register_fd_cache_lists(): registering FF list %s for device %02u:%02u failed with error %s!\n",
				     tmp,
				     device_p->major, device_p->minor,
				     get_error_name(tmp2, err));
			rsbac_kfree(tmp2);
		}
	} else
		rsbac_list_lol_max_items(device_p->fd_cache_handle[SW_FF],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_RC)
	sprintf(tmp, "%sRC", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &(device_p->fd_cache_handle[SW_RC]), list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  device_p->major, device_p->minor,
				  RSBAC_LIST_MIN_MAX_HASH_BITS,
				  rsbac_list_hash_fd,
				  NULL);
	if (err) {
		char *tmp2;

		tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp2) {
			rsbac_printk(KERN_WARNING "register_fd_cache_lists(): registering RC list %s for device %02u:%02u failed with error %s!\n",
				     tmp,
				     device_p->major, device_p->minor,
				     get_error_name(tmp2, err));
			rsbac_kfree(tmp2);
		}
	} else
		rsbac_list_lol_max_items(device_p->fd_cache_handle[SW_RC],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_UDF)
	sprintf(tmp, "%sUDF", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &(device_p->fd_cache_handle[SW_UDF]), list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  device_p->major, device_p->minor,
				  RSBAC_LIST_MIN_MAX_HASH_BITS,
				  rsbac_list_hash_fd,
				  NULL);
	if (err) {
		char *tmp2;

		tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp2) {
			rsbac_printk(KERN_WARNING "register_fd_cache_lists(): registering UDF list %s for device %02u:%02u failed with error %s!\n",
				     tmp,
				     device_p->major, device_p->minor,
				     get_error_name(tmp2, err));
			rsbac_kfree(tmp2);
		}
	} else
		rsbac_list_lol_max_items(device_p->fd_cache_handle[SW_UDF],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS,
			A_none);
#endif

	rsbac_kfree(list_info_p);
	rsbac_kfree(tmp);
	return err;
}

static int unregister_fd_cache_lists(struct rsbac_device_list_item_t *device_p)
{
	u_int i;
	int err;
	rsbac_list_handle_t tmp_handle;

	rsbac_pr_debug(fdcache, "unregistering FD Cache lists for device %02u:%02u\n",
			device_p->major, device_p->minor);
	for (i = 0; i < SW_NONE; i++) {
		if (device_p->fd_cache_handle[i]) {
			tmp_handle = device_p->fd_cache_handle[i];
			device_p->fd_cache_handle[i] = NULL;
			err = rsbac_list_lol_detach(&tmp_handle, RSBAC_FD_CACHE_KEY);
			if (err) {
				char *tmp2;

				device_p->fd_cache_handle[i] = tmp_handle;
				tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);
				if (tmp2) {
					rsbac_printk(KERN_WARNING "unregister_fd_cache_lists(): unregistering list for device %02u:%02u, module %u failed with error %s!\n",
						     device_p->major, device_p->minor,
						     i,
						     get_error_name(tmp2, err));
					rsbac_kfree(tmp2);
				}
			}
		}
	}
	return 0;
}
#endif


/* Create a device item without adding to list. No locking needed. */
static struct rsbac_device_list_item_t
*create_device_item(struct vfsmount *vfsmount_p, __u32 major, __u32 minor)
{
	struct rsbac_device_list_item_t *new_item_p;

	/* allocate memory for new device, return NULL, if failed */
	if (!(new_item_p = rsbac_smalloc_clear_unlocked(device_item_slab)))
		return NULL;

	new_item_p->major = major;
	new_item_p->minor = minor;
	new_item_p->vfsmount_p = vfsmount_p;
	new_item_p->mount_count = 1;
	new_item_p->persist = FALSE;

	return new_item_p;
}

/* Add an existing device item to list. Locking needed. */
static struct rsbac_device_list_item_t
*add_device_item(struct rsbac_device_list_item_t *device_p, rsbac_boolean_t may_sync)
{
	struct rsbac_device_list_head_t * new_p;
	struct rsbac_device_list_head_t * old_p;
	u_int hash;

	if (!device_p)
		return NULL;

	hash = device_hash(device_p->minor);
	spin_lock(&device_list_locks[hash]);
	old_p = device_head_p[hash];
	new_p = rsbac_kmalloc(sizeof(*new_p));
	*new_p = *old_p;
	/* add new device to device list */
	if (!new_p->head) {	/* first device */
		new_p->head = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count = 1;
		device_p->prev = NULL;
		device_p->next = NULL;
	} else {		/* there is another device -> hang to tail */
		device_p->prev = new_p->tail;
		device_p->next = NULL;
		new_p->tail->next = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count++;
	}
	rcu_assign_pointer(device_head_p[hash], new_p);
	spin_unlock(&device_list_locks[hash]);
	if (may_sync) {
		synchronize_srcu(&device_list_srcu[hash]);
		rsbac_kfree(old_p);
	} else {
		rsbac_delayed_kfree(old_p, 10);
	}
	return device_p;
}

/************************************************************************** */
/* The remove_item() functions remove an item from the list. If this item   */
/* is head, tail or curr, these pointers are set accordingly.               */
/* To speed up removing several subsequent items, curr is set to the next   */
/* item, if possible.                                                       */
/* If the item is not found, nothing is done.                               */

static void clear_device_item(struct rsbac_device_list_item_t *item_p)
{
	if (!item_p)
		return;

	/* OK, lets remove the device item itself */
	rsbac_sfree(device_item_slab, item_p);
}

/* remove_device_item unlocks device_list_locks[hash]! */
static void remove_device_item(__u32 major, __u32 minor, u_int hash)
{
	struct rsbac_device_list_item_t *item_p;
      
	if ((item_p = lookup_device_locked(major, minor, hash))) {
		struct rsbac_device_list_head_t * new_p;
		struct rsbac_device_list_head_t * old_p;

		old_p = device_head_p[hash];
		new_p = rsbac_kmalloc(sizeof(*new_p));
		if (!new_p) {
			/* Ouch! */
			spin_unlock(&device_list_locks[hash]);
			return;
		}
		*new_p = *old_p;
		if (new_p->head == item_p) {	/* item is head */
			if (new_p->tail == item_p) {	/* item is head and tail = only item -> list will be empty */
				new_p->head = NULL;
				new_p->tail = NULL;
			} else {	/* item is head, but not tail -> next item becomes head */
				item_p->next->prev = NULL;
				new_p->head = item_p->next;
			}
		} else {	/* item is not head */
			if (new_p->tail == item_p) {	/*item is not head, but tail -> previous item becomes tail */
				item_p->prev->next = NULL;
				new_p->tail = item_p->prev;
			} else {	/* item is neither head nor tail -> item is cut out */
				item_p->prev->next = item_p->next;
				item_p->next->prev = item_p->prev;
			}
		}

		/* curr is no longer valid -> reset.                              */
		new_p->curr = NULL;
		/* adjust counter */
		new_p->count--;
		rcu_assign_pointer(device_head_p[hash], new_p);
		spin_unlock(&device_list_locks[hash]);
		synchronize_srcu(&device_list_srcu[hash]);
		rsbac_kfree(old_p);
	} else {
		spin_unlock(&device_list_locks[hash]);
	}
}

/**************************************************/
/*       Externally visible help functions        */
/**************************************************/

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_get_vfsmount);
#endif
struct vfsmount *rsbac_get_vfsmount(__u32 major, __u32 minor)
{
	struct rsbac_device_list_item_t *device_p;
	struct vfsmount *vfsmount_p;
	u_int hash;
	int srcu_idx;

	if (RSBAC_IS_AUTO_DEV(major, minor))
		return NULL;

	hash = device_hash(minor);
	/* get super_block-pointer */
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	if (!device_p) {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			rsbac_printk(KERN_WARNING "rsbac_get_vfsmount(): unknown device %02u:%02u\n",
				     major, minor);
			return NULL;
	}
	vfsmount_p = device_p->vfsmount_p;
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	return vfsmount_p;
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_read_open);
#endif
long rsbac_read_open(char *name, __u32 major, __u32 minor)
{
	long dir_fd;
	long file_fd;
	struct open_how how = build_open_how(O_RDONLY, 0);
	struct open_flags op;
	struct file * f2;
	struct filename *fname;
	struct vfsmount *vfsmount_p;

	vfsmount_p = rsbac_get_vfsmount(major, minor);
	if (!vfsmount_p) {
		rsbac_pr_debug(ds, "device %02u:%02u has no vfsmount_p!\n",
				major, minor);
		return -RSBAC_EINVALIDDEV;
	}

	dir_fd = rsbac_aci_path_open(vfsmount_p, major, minor, FALSE);
	if (dir_fd < 0) {
		rsbac_pr_debug(ds, "could not get dir fd for dev %02u:%02u, error %li\n",
				major, minor, dir_fd);
		return -RSBAC_ENOTFOUND;
	}

	file_fd = build_open_flags(&how, &op);
	file_fd = get_unused_fd_flags(how.flags);
	fname = getname_kernel(name);
	f2 = do_filp_open(dir_fd, fname, &op);
	putname(fname);
	if (IS_ERR(f2)) {
		/* file not found: trying backup */
		char *bname;
		int name_len = strlen(name);

		bname = rsbac_kmalloc(name_len + 2);
		if (!bname) {
			rsbac_aci_path_close(dir_fd);
			put_unused_fd(file_fd);
			return -RSBAC_ENOMEM;
		}
		strcpy(bname, name);
		bname[name_len] = 'b';
		name_len++;
		bname[name_len] = (char) 0;
		rsbac_pr_debug(ds, "could not lookup file %s, trying backup %s\n",
			     name, bname);
		fname = getname_kernel(bname);
		rsbac_kfree(bname);
		f2 = do_filp_open(dir_fd, fname, &op);
		putname(fname);
	}
	rsbac_aci_path_close(dir_fd);
	if (!IS_ERR(f2)) {
		fsnotify_open(f2);
		fd_install(file_fd, f2);
		return file_fd;
	}
	put_unused_fd(file_fd);
	return PTR_ERR(f2);
}

static int rsbac_rename(struct mnt_idmap * rsbac_mnt_idmap, int dir_fd, const char * name)
{
	struct dentry * dir_dentry;
	struct dentry * old_dentry;
	struct dentry * new_dentry;
	struct inode *delegated_inode = NULL;
	struct file *file;
	struct fdtable *fdt;
	int error;
	char bname[RSBAC_MAXNAMELEN];
	const u_int name_len = strlen(name);
	struct renamedata reda;

	if (name_len > RSBAC_MAXNAMELEN - 2) {
		rsbac_pr_debug(ds, "rsbac_rename(): name %s too long, no rename possible\n",
				name);
		return 0;
	}

	spin_lock(&current->files->file_lock);
	fdt = files_fdtable(current->files);
	file = fdt->fd[dir_fd];
	spin_unlock(&current->files->file_lock);
	if (!file) {
		rsbac_pr_debug(ds, "rsbac_rename(): dir_fd not found, no rename possible\n");
		return -RSBAC_ENOTFOUND;
	}

	dir_dentry = file->f_path.dentry;

	inode_lock(dir_dentry->d_inode);
	old_dentry = lookup_one(&nop_mnt_idmap, &QSTR(name),
				 dir_dentry);
	if (!old_dentry || IS_ERR(dir_dentry)) {
		inode_unlock(dir_dentry->d_inode);
		rsbac_pr_debug(ds, "rsbac_rename(): old name %s not found, no rename needed\n",
				name);
		return 0;
	}
	if (!old_dentry->d_inode) {
		inode_unlock(dir_dentry->d_inode);
		dput(old_dentry);
		rsbac_pr_debug(ds, "rsbac_rename(): old name %s found without inode, no rename needed\n",
				name);
		return 0;
	}
	strcpy(bname, name);
	bname[name_len] = 'b';
	bname[name_len + 1] = (char) 0;
	new_dentry = lookup_one(&nop_mnt_idmap, &QSTR(bname),
				 dir_dentry);
	if (RSBAC_IS_INVALID_PTR(new_dentry)) {
		inode_unlock(dir_dentry->d_inode);
		dput(old_dentry);
		rsbac_pr_debug(ds, "rsbac_rename(): new name %s not found, no rename possible\n",
				bname);
		return -RSBAC_ENOTFOUND;
	}

	reda.mnt_idmap = rsbac_mnt_idmap;
	reda.old_parent = dir_dentry;
	reda.old_dentry = old_dentry;
	reda.new_parent = dir_dentry;
	reda.new_dentry = new_dentry;
	reda.delegated_inode = &delegated_inode;
	reda.flags = 0;
	error = vfs_rename(&reda);

	inode_unlock(dir_dentry->d_inode);
	dput(old_dentry);
	dput(new_dentry);

	return error;
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_write_open);
#endif
long rsbac_write_open(char *name, __u32 major, __u32 minor)
{
	long dir_fd;
	long file_fd;
	struct open_how how = build_open_how(O_RDONLY, 0);
	struct open_flags op;
	struct file * f2;
	struct filename *fname;
	struct vfsmount *vfsmount_p;

	vfsmount_p = rsbac_get_vfsmount(major, minor);
	if (!vfsmount_p) {
		rsbac_pr_debug(ds, "device %02u:%02u has no vfsmount_p!\n",
				major, minor);
		return -RSBAC_EINVALIDDEV;
	}

	dir_fd = rsbac_aci_path_open(vfsmount_p, major, minor, TRUE);
	if (dir_fd < 0) {
		if (dir_fd != -RSBAC_ENOTWRITABLE) {
			rsbac_printk(KERN_WARNING "rsbac_write_open(): could not get dir fd for device %02u:%02u, error %li!\n",
				major, minor, dir_fd);
			return -RSBAC_EWRITEFAILED;
		}
		return -RSBAC_ENOTWRITABLE;
	}

	file_fd = rsbac_rename(mnt_idmap(vfsmount_p), dir_fd, name);
	if (file_fd < 0) {
		rsbac_printk(KERN_WARNING "rsbac_write_open(): failed to rename old file %s on device %02u:%02u to backup %sb, error %li\n",
			name, major, minor, name, file_fd);
	}

	how = build_open_how(O_RDWR | O_CREAT | O_TRUNC, 0);
	file_fd = build_open_flags(&how, &op);
	file_fd = get_unused_fd_flags(how.flags);
	fname = getname_kernel(name);
	f2 = do_filp_open(dir_fd, fname, &op);
	putname(fname);
	rsbac_aci_path_close(dir_fd);
	if (!IS_ERR(f2)) {
		fsnotify_open(f2);
		fd_install(file_fd, f2);
		return file_fd;
	}
	rsbac_printk(KERN_WARNING "rsbac_write_open(): failed to open file %s on device %02u:%02u for writing, error %li\n",
			name, major, minor, PTR_ERR(f2));
	put_unused_fd(file_fd);
	return PTR_ERR(f2);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_read_close);
#endif
void rsbac_read_close(unsigned int fd)
{
	close_fd(fd);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_write_close);
#endif
void rsbac_write_close(unsigned int fd)
{
	close_fd(fd);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_read_file);
#endif
/* buf must point to kernel space */
ssize_t rsbac_read_file(unsigned int fd, char *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (fd_file(f)) {
		loff_t pos;
		loff_t *ppos;

		if (!(fd_file(f)->f_mode & FMODE_READ))
			return -EBADF;
		if (!(fd_file(f)->f_mode & FMODE_CAN_READ))
			return -EINVAL;
		ppos = &fd_file(f)->f_pos;
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = kernel_read(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_write_file);
#endif
/* buf must point to kernel space */
ssize_t rsbac_write_file(unsigned int fd, const char *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (fd_file(f)) {
		loff_t pos;
		loff_t *ppos;

		if (!(fd_file(f)->f_mode & FMODE_WRITE))
			return -EBADF;
		if (!(fd_file(f)->f_mode & FMODE_CAN_WRITE))
			return -EINVAL;
		ppos = &fd_file(f)->f_pos;
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = kernel_write(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}


#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_lookup_full_path);
#endif
int rsbac_lookup_full_path(struct dentry *dentry_p, char path[], int maxlen, int pseudonymize)
{
	int len = 0;
	char *i_path;
	int tmplen = 0;
#ifdef CONFIG_RSBAC_LOG_PSEUDO_FS
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val;
#endif
	int srcu_idx;

	if (!dentry_p || !path)
		return -RSBAC_EINVALIDPOINTER;
	if (maxlen <= 0)
		return -RSBAC_EINVALIDVALUE;
	i_path = rsbac_kmalloc(maxlen + RSBAC_MAXNAMELEN);
	if (!i_path)
		return -RSBAC_ENOMEM;

	path[0] = 0;

	while (dentry_p && (len < maxlen) && dentry_p->d_name.len
	       && dentry_p->d_name.name) {
#ifdef CONFIG_RSBAC_LOG_PSEUDO_FS
		if (   pseudonymize
		    && dentry_p->d_inode
		    && dentry_p->d_parent
		    && dentry_p->d_parent->d_inode
		    && (i_tid.user = __kuid_val(dentry_p->d_inode->i_uid))
		    && (__kuid_val(dentry_p->d_inode->i_uid) !=
			__kuid_val(dentry_p->d_parent->d_inode->i_uid))
		    && !rsbac_get_attr(SW_GEN, T_USER, i_tid, A_pseudo,
				       &i_attr_val, FALSE)
		    && i_attr_val.pseudo) {	/* Max len of 32 Bit value in decimal print is 11 */
			if ((maxlen - len) < 12) {
				rsbac_kfree(i_path);
				return len;
			}
			tmplen =
			    snprintf(i_path, 11, "%u", i_attr_val.pseudo);
		} else
#endif
		{
			tmplen = dentry_p->d_name.len;
			if ((tmplen + 1) > (maxlen - len)) {
				rsbac_kfree(i_path);
				return len;
			}
			strncpy(i_path, dentry_p->d_name.name, tmplen);
		}
		/* Skip double / on multi mounts.
		 * Last / is appended at the end of the function */
		if((i_path[tmplen-1] != '/') && (tmplen != 1)) {
			if(len && (i_path[tmplen-1] != '/')) {
				i_path[tmplen] = '/';
				tmplen++;
			}
			i_path[tmplen]=0;
			strcat(i_path, path);
			strcpy(path, i_path);
			len += tmplen;
		}
		if (dentry_p->d_parent && (dentry_p->d_parent != dentry_p)
		    && (dentry_p->d_sb->s_root != dentry_p)
		    )
			dentry_p = dentry_p->d_parent;
		else {
			struct rsbac_device_list_item_t *device_p;
			u_int hash;
			__u32 major;
			__u32 minor;

			if (dentry_p->d_sb->s_dev == rsbac_root_dev) {
				break;
			}
			major = RSBAC_MAJOR(dentry_p->d_sb->s_dev);
			minor = RSBAC_MINOR(dentry_p->d_sb->s_dev);
			hash = device_hash(minor);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(major, minor, hash);
			if (   device_p
			    && device_p->vfsmount_p
			    && real_mount(device_p->vfsmount_p)->mnt_mountpoint
			    && real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb
			    && (real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb->s_dev != dentry_p->d_sb->s_dev)
			   ) {
				dentry_p = real_mount(device_p->vfsmount_p)->mnt_mountpoint;
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			} else {
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				break;
			}
		}
	}
	
	i_path[tmplen]=0;
	strcat(i_path, path);
	strcpy(path, i_path);
	
	rsbac_kfree(i_path);
	return len;
}

/************************************************* */
/*               proc fs functions                 */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
devices_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	u_int count = 0;
	u_int i;
	int srcu_idx;
	int parent_dev;

	if (!rsbac_initialized)
		return -ENOSYS;

	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++)
		count += device_head_p[i]->count;
	seq_printf(m, "%u RSBAC Devices\n---------------\nHash size is %lu, item size is %zu\n",
		       count, BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS), sizeof(*device_p));
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	seq_printf(m, "write_blocked is %u\n", write_blocked);
#endif
	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		for (device_p = srcu_dereference(head_p->head, &device_list_srcu[i]); device_p;
		     device_p = srcu_dereference(device_p->next, &device_list_srcu[i])) {
			if (   device_p->vfsmount_p
			    && !RSBAC_IS_INVALID_PTR(device_p->vfsmount_p->mnt_sb)
			    && device_p->vfsmount_p->mnt_sb->s_type
			    && device_p->vfsmount_p->mnt_sb->s_type->name
			    && real_mount(device_p->vfsmount_p)->mnt_mountpoint) {
				parent_dev = real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb->s_dev;
				seq_printf(m,
					    "%02u:%02u mount_count %u, fs_type %s (%lx), mountpoint %s, parent %02u:%02u, persist %u, rsbac_dir_inode %llu\n",
					    device_p->major, device_p->minor,
					    device_p->mount_count,
					    device_p->vfsmount_p->mnt_sb->s_type->name,
					    device_p->vfsmount_p->mnt_sb->s_magic,
					    real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_name.name,
					    parent_dev != RSBAC_MKDEV(device_p->major, device_p->minor) ? RSBAC_MAJOR(parent_dev) : 0,
					    parent_dev != RSBAC_MKDEV(device_p->major, device_p->minor) ? RSBAC_MINOR(parent_dev) : 0,
					    device_p->persist,
					    device_p->rsbac_dir_inode);
			} else
				    seq_printf(m,
					    "%02u:%02u mount_count %u, no vfsmount_p, persist %u\n",
					    device_p->major, device_p->minor,
					    device_p->mount_count,
					    device_p->persist);
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	return 0;
}

static int devices_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, devices_proc_show, NULL);
}

static const struct proc_ops devices_proc_ops = {
       .proc_open           = devices_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *devices;

static int
stats_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	long fd_count, fd_dev_count;
	u_long fd_sum = 0;
	u_long sum = 0;
	u_long total_sum = 0;
	long tmp_count;
	int i;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}
	seq_printf(m, "RSBAC Status\n------------\nRSBAC Version: %s, API min: %s, API max: %s\nCompiled Modules:%s\n",
		    RSBAC_VERSION, RSBAC_API_MIN_VERSION, RSBAC_API_MAX_VERSION, compiled_modules);
#ifdef CONFIG_RSBAC_SWITCH
	{
		char *active_modules;

		active_modules = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (active_modules) {
			active_modules[0] = (char) 0;
#ifdef CONFIG_RSBAC_REG
			strcat(active_modules, " REG");
#endif
#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_SWITCH_MAC
			if (rsbac_switch_mac)
#endif
#ifdef CONFIG_RSBAC_MAC_LIGHT
				strcat(active_modules, " MAC-L");
#else
				strcat(active_modules, " MAC");
#endif
#endif
#ifdef CONFIG_RSBAC_FF
#ifdef CONFIG_RSBAC_SWITCH_FF
			if (rsbac_switch_ff)
#endif
				strcat(active_modules, " FF");
#endif
#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
			if (rsbac_switch_rc)
#endif
				strcat(active_modules, " RC");
#endif
#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
			if (rsbac_switch_auth)
#endif
				strcat(active_modules, " AUTH");
#endif
#ifdef CONFIG_RSBAC_ACL
#ifdef CONFIG_RSBAC_SWITCH_ACL
			if (rsbac_switch_acl)
#endif
				strcat(active_modules, " ACL");
#endif
#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
			if (rsbac_switch_cap)
#endif
				strcat(active_modules, " CAP");
#endif
#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
			if (rsbac_switch_jail)
#endif
				strcat(active_modules, " JAIL");
#endif
#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
			if (rsbac_switch_res)
#endif
				strcat(active_modules, " RES");
#endif
#ifdef CONFIG_RSBAC_UDF
#ifdef CONFIG_RSBAC_SWITCH_UDF
			if (rsbac_switch_udf)
#endif
				strcat(active_modules, " UDF");
#endif
			seq_printf(m, "Active Modules:  %s\n",
				    active_modules);
			rsbac_kfree(active_modules);
		}
	}
#else
	seq_printf(m, "All modules active (no switching)\n");
#endif

#ifdef CONFIG_RSBAC_SOFTMODE
	if (rsbac_softmode) {
#ifdef CONFIG_RSBAC_SOFTMODE_IND
		seq_printf(m, "Global softmode is enabled\n");
#else
		seq_printf(m, "Softmode is enabled\n");
#endif
	} else {
#ifdef CONFIG_RSBAC_SOFTMODE_IND
		seq_printf(m, "Global softmode is disabled\n");
#else
		seq_printf(m, "Softmode is disabled\n");
#endif
	}
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	{
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			  seq_printf(m,
				    "Individual softmode enabled for:");
			for (i = 0; i <= RSBAC_MAX_MOD; i++)
				if (rsbac_ind_softmode[i])
					 seq_printf(m, " %s",
						    get_switch_target_name
						    (tmp, i));
			rsbac_kfree(tmp);
			seq_printf(m, "\n");
		}
	}
#endif
#endif

	seq_printf(m, "\n");

	tmp_count = 0;
	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
		if (device_p)
			seq_printf(m, "FD items:\n");
		while (device_p) {
			fd_dev_count = 0;
			fd_count = rsbac_list_count(device_p->handles.gen);
			if (fd_count >= 0) {
				seq_printf(m, "Dev %02u:%02u: %lu GEN",
						device_p->major, device_p->minor,
						fd_count);
				fd_dev_count += fd_count;
			}

#if defined(CONFIG_RSBAC_MAC)
			fd_count = rsbac_list_count(device_p->handles.mac);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu MAC", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_FF)
			fd_count = rsbac_list_count(device_p->handles.ff);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu FF", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RC)
			fd_count = rsbac_list_count(device_p->handles.rc);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu RC", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_AUTH)
			fd_count = rsbac_list_count(device_p->handles.auth);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu AUTH", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_CAP)
			fd_count = rsbac_list_count(device_p->handles.cap);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu CAP", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RES)
			fd_count = rsbac_list_lol_count(device_p->handles.res_min);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu RES MIN", fd_count);
				fd_dev_count += fd_count;
			}
			fd_count = rsbac_list_lol_count(device_p->handles.res_max);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu RES MAX", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_UDF)
			fd_count = rsbac_list_count(device_p->handles.udf);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu UDF", fd_count);
				fd_dev_count += fd_count;
			}
#if defined(CONFIG_RSBAC_UDF_CACHE)
			fd_count = rsbac_list_count(device_p->handles.udfc);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu UDF CHECKED", fd_count);
				fd_dev_count += fd_count;
			}
#endif
#endif

			seq_printf(m, ", %lu total\n",
				       fd_dev_count);
			fd_sum += fd_dev_count;
			device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
		}
		tmp_count += device_head_p[i]->count;
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	seq_printf(m,
		    "Sum of %lu Devices with %lu fd-items\n\n",
		    tmp_count, fd_sum);
	total_sum += fd_sum;
	/* dev lists */
	sum = 0;
	tmp_count = rsbac_list_count(dev_handles.gen);
	seq_printf(m, "DEV: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(dev_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(dev_major_handles.rc);
	seq_printf(m, ", %lu major RC", tmp_count);
	sum += tmp_count;
	tmp_count = rsbac_list_count(dev_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* ipc lists */
	sum = 0;
	seq_printf(m, "IPC: 0 GEN");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(ipc_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(ipc_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(ipc_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* user lists */
	sum = 0;
	tmp_count = rsbac_list_count(user_handles.gen);
	seq_printf(m, "USER: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(user_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_FF)
	tmp_count = rsbac_list_count(user_handles.ff);
	seq_printf(m, ", %lu FF", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(user_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(user_handles.auth);
	seq_printf(m, ", %lu AUTH", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(user_handles.cap);
	seq_printf(m, ", %lu CAP", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(user_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_list_lol_count(user_handles.res_min);
	seq_printf(m, ", %lu RES MIN", tmp_count);
	sum += tmp_count;
	tmp_count = rsbac_list_lol_count(user_handles.res_max);
	seq_printf(m, ", %lu RES MAX", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_UDF)
	tmp_count = rsbac_list_count(user_handles.udf);
	seq_printf(m, ", %lu UDF", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* process lists */
	sum = 0;
	tmp_count = rsbac_list_count(process_handles.gen);
	seq_printf(m, "PROCESS: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(process_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(process_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(process_handles.auth);
	seq_printf(m, ", %lu AUTH", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(process_handles.cap);
	seq_printf(m, ", %lu CAP", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(process_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_UDF)
	tmp_count = rsbac_list_count(process_handles.udf);
	seq_printf(m, ", %lu UDF", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
#if defined(CONFIG_RSBAC_UM)
	/* group lists */
	sum = 0;
	seq_printf(m, "GROUP:");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	tmp_count = rsbac_list_count(group_handles.rc);
	seq_printf(m, " %lu RC,", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, " %lu total\n", sum);
	total_sum += sum;
#endif

#if defined(CONFIG_RSBAC_NET_DEV)
	/* netdev lists */
	sum = 0;
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	tmp_count = rsbac_list_count(netdev_handles.gen);
	seq_printf(m, "NETDEV: %lu GEN, ", tmp_count);
	sum += tmp_count;
#else
	seq_printf(m, "NETDEV: ");
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(netdev_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	/* net template list */
	tmp_count = rsbac_list_count(net_temp_handle);
	seq_printf(m, "%lu Network Templates\n", tmp_count);
	/* nettemp lists */
	sum = 0;
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	tmp_count = rsbac_list_count(nettemp_handles.gen);
	seq_printf(m, "NETTEMP: %lu GEN, ", tmp_count);
	sum += tmp_count;
#else
	seq_printf(m, "NETTEMP: ");
#endif
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(nettemp_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(nettemp_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
	/* local netobj lists */
	sum = 0;
	seq_printf(m, "LNETOBJ: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(lnetobj_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	tmp_count = rsbac_list_count(lnetobj_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
	/* remote netobj lists */
	sum = 0;
	seq_printf(m, "RNETOBJ: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(rnetobj_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	tmp_count = rsbac_list_count(rnetobj_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
#endif				/* NET_OBJ */

	seq_printf(m,
		       "Total sum of %lu registered rsbac-items\n",
		       total_sum);
	seq_printf(m,
		       "\nadf_request calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, total: %llu\n",
		       rsbac_adf_request_count[T_FILE],
		       rsbac_adf_request_count[T_DIR],
		       rsbac_adf_request_count[T_FIFO],
		       rsbac_adf_request_count[T_SYMLINK],
		       rsbac_adf_request_count[T_DEV],
		       rsbac_adf_request_count[T_IPC],
		       rsbac_adf_request_count[T_SCD],
		       rsbac_adf_request_count[T_USER],
		       rsbac_adf_request_count[T_PROCESS],
		       rsbac_adf_request_count[T_NETDEV],
		       rsbac_adf_request_count[T_NETTEMP],
		       rsbac_adf_request_count[T_NETOBJ],
		       rsbac_adf_request_count[T_GROUP],
		       rsbac_adf_request_count[T_UNIXSOCK],
		       rsbac_adf_request_count[T_FILE]+rsbac_adf_request_count[T_DIR]+rsbac_adf_request_count[T_FIFO]+rsbac_adf_request_count[T_SYMLINK]+rsbac_adf_request_count[T_DEV]+rsbac_adf_request_count[T_IPC]+rsbac_adf_request_count[T_SCD]+rsbac_adf_request_count[T_USER]+rsbac_adf_request_count[T_PROCESS]+rsbac_adf_request_count[T_NETDEV]+rsbac_adf_request_count[T_NETTEMP]+rsbac_adf_request_count[T_NETOBJ]+rsbac_adf_request_count[T_GROUP]+rsbac_adf_request_count[T_UNIXSOCK]);
	seq_printf(m,
		       "adf_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, total: %llu\n",
		       rsbac_adf_set_attr_count[T_FILE],
		       rsbac_adf_set_attr_count[T_DIR],
		       rsbac_adf_set_attr_count[T_FIFO],
		       rsbac_adf_set_attr_count[T_SYMLINK],
		       rsbac_adf_set_attr_count[T_DEV],
		       rsbac_adf_set_attr_count[T_IPC],
		       rsbac_adf_set_attr_count[T_SCD],
		       rsbac_adf_set_attr_count[T_USER],
		       rsbac_adf_set_attr_count[T_PROCESS],
		       rsbac_adf_set_attr_count[T_NETDEV],
		       rsbac_adf_set_attr_count[T_NETTEMP],
		       rsbac_adf_set_attr_count[T_NETOBJ],
		       rsbac_adf_set_attr_count[T_GROUP],
		       rsbac_adf_set_attr_count[T_UNIXSOCK],
		       rsbac_adf_set_attr_count[T_FILE]+rsbac_adf_set_attr_count[T_DIR]+rsbac_adf_set_attr_count[T_FIFO]+rsbac_adf_set_attr_count[T_SYMLINK]+rsbac_adf_set_attr_count[T_DEV]+rsbac_adf_set_attr_count[T_IPC]+rsbac_adf_set_attr_count[T_SCD]+rsbac_adf_set_attr_count[T_USER]+rsbac_adf_set_attr_count[T_PROCESS]+rsbac_adf_set_attr_count[T_NETDEV]+rsbac_adf_set_attr_count[T_NETTEMP]+rsbac_adf_set_attr_count[T_NETOBJ]+rsbac_adf_set_attr_count[T_GROUP]+rsbac_adf_set_attr_count[T_UNIXSOCK]);
	return 0;
}

static int stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_proc_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
       .proc_open           = stats_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *stats;

static int
active_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "Version: %s, API min: %s, API max: %s\n",
		    RSBAC_VERSION, RSBAC_API_MIN_VERSION, RSBAC_API_MAX_VERSION);
#ifdef CONFIG_RSBAC_SOFTMODE
	if (rsbac_softmode)
		seq_printf(m, "Mode: SOFTMODE\n");
	else
#endif
		seq_printf(m, "Mode: Secure\n");
#ifdef CONFIG_RSBAC_SOFTMODE
	seq_printf(m, "Softmode: available\n");
#else
	seq_printf(m, "Softmode: unavailable\n");
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	seq_printf(m, "Ind-Soft: available\n");
#else
	seq_printf(m, "Ind-Soft: unavailable\n");
#endif
#ifdef CONFIG_RSBAC_SWITCH
	seq_printf(m, "Switching off: available for");
#ifdef CONFIG_RSBAC_SWITCH_MAC
#ifndef CONFIG_RSBAC_SWITCH_ON
	if (rsbac_switch_mac)
#endif
		seq_printf(m, " MAC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_FF
	seq_printf(m, " FF");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RC
#ifndef CONFIG_RSBAC_SWITCH_ON
	if (rsbac_switch_rc)
#endif
		seq_printf(m, " RC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	seq_printf(m, " AUTH");
#endif
#ifdef CONFIG_RSBAC_SWITCH_ACL
	seq_printf(m, " ACL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_CAP
	seq_printf(m, " CAP");
#endif
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	seq_printf(m, " JAIL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RES
	seq_printf(m, " RES");
#endif
#ifdef CONFIG_RSBAC_SWITCH_UDF
	seq_printf(m, " UDF");
#endif
	seq_printf(m, "\n");
#ifdef CONFIG_RSBAC_SWITCH_ON
	seq_printf(m, "Switching on: available for");
#ifdef CONFIG_RSBAC_SWITCH_MAC
	seq_printf(m, " MAC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RC
	seq_printf(m, " RC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_FF
	seq_printf(m, " FF");
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	seq_printf(m, " AUTH");
#endif
#ifdef CONFIG_RSBAC_SWITCH_ACL
	seq_printf(m, " ACL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_CAP
	seq_printf(m, " CAP");
#endif
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	seq_printf(m, " JAIL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RES
	seq_printf(m, " RES");
#endif
#ifdef CONFIG_RSBAC_SWITCH_UDF
	seq_printf(m, " UDF");
#endif
#ifdef CONFIG_RSBAC_SWITCH_MPROTECT
	seq_printf(m, " MPROTECT");
#endif
	seq_printf(m, "\n");
#endif // CONFIG_RSBAC_SWITCH_ON
#else // CONFIG_RSBAC_SWITCH
	seq_printf(m, "Switching off: unavailable\n");
	seq_printf(m, "Switching on: unavailable\n");
#endif // CONFIG_RSBAC_SWITCH

#ifdef CONFIG_RSBAC_REG
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_REG])
		seq_printf(m, "Module: REG  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: REG  on\n");
#endif

#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_SWITCH_MAC
	if (!rsbac_switch_mac)
		seq_printf(m, "Module: MAC  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_MAC])
		seq_printf(m, "Module: MAC  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: MAC  on\n");
#endif

#ifdef CONFIG_RSBAC_FF
#ifdef CONFIG_RSBAC_SWITCH_FF
	if (!rsbac_switch_ff)
		seq_printf(m, "Module: FF   OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_FF])
		seq_printf(m, "Module: FF   SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: FF   on\n");
#endif

#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
	if (!rsbac_switch_rc)
		seq_printf(m, "Module: RC   OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_RC])
		seq_printf(m, "Module: RC   SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: RC   on\n");
#endif

#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	if (!rsbac_switch_auth)
		seq_printf(m, "Module: AUTH OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_AUTH])
		seq_printf(m, "Module: AUTH SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: AUTH on\n");
#endif

#ifdef CONFIG_RSBAC_ACL
#ifdef CONFIG_RSBAC_SWITCH_ACL
	if (!rsbac_switch_acl)
		seq_printf(m, "Module: ACL  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_ACL])
		seq_printf(m, "Module: ACL  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: ACL  on\n");
#endif

#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
	if (!rsbac_switch_cap)
		seq_printf(m, "Module: CAP  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_CAP])
		seq_printf(m, "Module: CAP  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: CAP  on\n");
#endif

#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	if (!rsbac_switch_jail)
		seq_printf(m, "Module: JAIL OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_JAIL])
		seq_printf(m, "Module: JAIL SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: JAIL on\n");
#endif

#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
	if (!rsbac_switch_res)
		seq_printf(m, "Module: RES  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_RES])
		seq_printf(m, "Module: RES  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: RES  on\n");
#endif

#ifdef CONFIG_RSBAC_UDF
#ifdef CONFIG_RSBAC_SWITCH_UDF
	if (!rsbac_switch_udf)
		seq_printf(m, "Module: UDF  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_UDF])
		seq_printf(m, "Module: UDF  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: UDF  on\n");
#endif

#ifdef CONFIG_RSBAC_MPROTECT
#ifdef CONFIG_RSBAC_SWITCH_MPROTECT
	if (!rsbac_switch_mprotect)
		seq_printf(m, "Module: MPROTECT OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_MPROTECT])
		seq_printf(m, "Module: MPROTECT SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: MPROTECT on\n");
#endif

	return 0;
}

static int active_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, active_proc_show, NULL);
}

static const struct proc_ops active_proc_ops = {
       .proc_open           = active_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *active;

#ifdef CONFIG_RSBAC_XSTATS
static int
xstats_proc_show(struct seq_file *m, void *v)
{
	int i, j;
	char name[80];
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
#ifdef CONFIG_RSBAC_FD_CACHE
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	int srcu_idx;
	int header_shown;
#endif

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		       "RSBAC ADF call Statistics\n-------------------------\nadf_request table:\n");
	seq_printf(m,
		    "Request /\tFILE\tDIR\tFIFO\tSYMLINK\tDEV\tIPC\tSCD\tUSER\tPROCESS\tNETDEV\tNETTEMP\tNETOBJ\tGROUP\tUNIXSOCK NONE");

	for (i = 0; i < R_NONE; i++) {
		get_request_name(name, i);
		name[15] = 0;
		seq_printf(m, "\n%-14s\t", name);
		for (j = 0; j <= T_NONE; j++) {
			if ((j == T_NETTEMP_NT)
			    || (j == T_FD)
			    )
				continue;
			seq_printf(m, "%llu\t",
				       rsbac_adf_request_xcount[j][i]);
		}
	}

	seq_printf(m,
		       "\n\nadf_request calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, none: %llu, total: %llu\n",
		       rsbac_adf_request_count[T_FILE],
		       rsbac_adf_request_count[T_DIR],
		       rsbac_adf_request_count[T_FIFO],
		       rsbac_adf_request_count[T_SYMLINK],
		       rsbac_adf_request_count[T_DEV],
		       rsbac_adf_request_count[T_IPC],
		       rsbac_adf_request_count[T_SCD],
		       rsbac_adf_request_count[T_USER],
		       rsbac_adf_request_count[T_PROCESS],
		       rsbac_adf_request_count[T_NETDEV],
		       rsbac_adf_request_count[T_NETTEMP],
		       rsbac_adf_request_count[T_NETOBJ],
		       rsbac_adf_request_count[T_GROUP],
		       rsbac_adf_request_count[T_UNIXSOCK],
		       rsbac_adf_request_count[T_NONE],
		       rsbac_adf_request_count[T_FILE]+rsbac_adf_request_count[T_DIR]+rsbac_adf_request_count[T_FIFO]+rsbac_adf_request_count[T_SYMLINK]+rsbac_adf_request_count[T_DEV]+rsbac_adf_request_count[T_IPC]+rsbac_adf_request_count[T_SCD]+rsbac_adf_request_count[T_USER]+rsbac_adf_request_count[T_PROCESS]+rsbac_adf_request_count[T_NETDEV]+rsbac_adf_request_count[T_NETTEMP]+rsbac_adf_request_count[T_NETOBJ]+rsbac_adf_request_count[T_GROUP]+rsbac_adf_request_count[T_UNIXSOCK]+rsbac_adf_request_count[T_NONE]);
	seq_printf(m,
		       "\n\nadf_set_attr table:\nRequest /\tFILE\tDIR\tFIFO\tSYMLINK\tDEV\tIPC\tSCD\tUSER\tPROCESS\tNETDEV\tNETTEMP\tNETOBJ\tGROUP\tUNIXSOCK NONE");
	for (i = 0; i < R_NONE; i++) {
		get_request_name(name, i);
		name[15] = 0;
		seq_printf(m, "\n%-14s\t", name);
		for (j = 0; j <= T_NONE; j++) {
			if ((j == T_NETTEMP_NT)
			    || (j == T_FD)
			    )
				continue;
			seq_printf(m, "%llu\t",
				       rsbac_adf_set_attr_xcount[j][i]);
		}
	}

	seq_printf(m,
		       "\n\nadf_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, none: %llu, total: %llu\n",
		       rsbac_adf_set_attr_count[T_FILE],
		       rsbac_adf_set_attr_count[T_DIR],
		       rsbac_adf_set_attr_count[T_FIFO],
		       rsbac_adf_set_attr_count[T_SYMLINK],
		       rsbac_adf_set_attr_count[T_DEV],
		       rsbac_adf_set_attr_count[T_IPC],
		       rsbac_adf_set_attr_count[T_SCD],
		       rsbac_adf_set_attr_count[T_USER],
		       rsbac_adf_set_attr_count[T_PROCESS],
		       rsbac_adf_set_attr_count[T_NETDEV],
		       rsbac_adf_set_attr_count[T_NETTEMP],
		       rsbac_adf_set_attr_count[T_NETOBJ],
		       rsbac_adf_set_attr_count[T_GROUP],
		       rsbac_adf_set_attr_count[T_UNIXSOCK],
		       rsbac_adf_set_attr_count[T_NONE],
		       rsbac_adf_set_attr_count[T_FILE]+rsbac_adf_set_attr_count[T_DIR]+rsbac_adf_set_attr_count[T_FIFO]+rsbac_adf_set_attr_count[T_SYMLINK]+rsbac_adf_set_attr_count[T_DEV]+rsbac_adf_set_attr_count[T_IPC]+rsbac_adf_set_attr_count[T_SCD]+rsbac_adf_set_attr_count[T_USER]+rsbac_adf_set_attr_count[T_PROCESS]+rsbac_adf_set_attr_count[T_NETDEV]+rsbac_adf_set_attr_count[T_NETTEMP]+rsbac_adf_set_attr_count[T_NETOBJ]+rsbac_adf_set_attr_count[T_GROUP]+rsbac_adf_set_attr_count[T_UNIXSOCK]+rsbac_adf_set_attr_count[T_NONE]);
	seq_printf(m,
		    "\nSyscall counts\n-------------\n");

	for (i = 0; i < RSYS_none; i++) {
		rsbac_get_syscall_name(name, i);
		name[30] = 0;
		seq_printf(m, "%-26s %llu\n",
			name, syscall_count[i]);
	}

	seq_printf(m,
		       "\n\nData Structures:\nrsbac_get_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       get_attr_count[T_FILE],
		       get_attr_count[T_DIR],
		       get_attr_count[T_FIFO],
		       get_attr_count[T_SYMLINK],
		       get_attr_count[T_DEV],
		       get_attr_count[T_IPC],
		       get_attr_count[T_SCD],
		       get_attr_count[T_USER],
		       get_attr_count[T_PROCESS],
		       get_attr_count[T_NETDEV],
		       get_attr_count[T_NETTEMP],
		       get_attr_count[T_NETOBJ],
		       get_attr_count[T_GROUP],
		       get_attr_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       set_attr_count[T_FILE],
		       set_attr_count[T_DIR],
		       set_attr_count[T_FIFO],
		       set_attr_count[T_SYMLINK],
		       set_attr_count[T_DEV],
		       set_attr_count[T_IPC],
		       set_attr_count[T_SCD],
		       set_attr_count[T_USER],
		       set_attr_count[T_PROCESS],
		       set_attr_count[T_NETDEV],
		       set_attr_count[T_NETTEMP],
		       set_attr_count[T_NETOBJ],
		       set_attr_count[T_GROUP],
		       set_attr_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_remove_target calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       remove_count[T_FILE],
		       remove_count[T_DIR],
		       remove_count[T_FIFO],
		       remove_count[T_SYMLINK],
		       remove_count[T_DEV],
		       remove_count[T_IPC],
		       remove_count[T_SCD],
		       remove_count[T_USER],
		       remove_count[T_PROCESS],
		       remove_count[T_NETDEV],
		       remove_count[T_NETTEMP],
		       remove_count[T_NETOBJ],
		       remove_count[T_GROUP],
		       remove_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_get_parent calls: %llu\n",
		       get_parent_count);

#ifdef CONFIG_RSBAC_FD_CACHE
	seq_printf(m, "\nFD Caches:\n");
	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
		while (device_p) {	/* for all sublists */
			header_shown = 0;
			for (j = 0; j < SW_NONE; j++) {
				if (device_p->fd_cache_handle[j]) {
					__u64 tmp_hits = device_p->fd_cache_hits[j];
					__u64 tmp_misses = device_p->fd_cache_misses[j];

					if (!header_shown) {
						seq_printf(m,
							"\n%02u:%02u    hits                 misses               items   subitem hm-ratio\n",
							device_p->major, device_p->minor);
						header_shown = 1;
					}
					while ((tmp_hits > (__u32) -1) || (tmp_misses > (__u32) -1)) {
						tmp_hits >>= 1;
						tmp_misses >>= 1;
					}
					if (!tmp_misses)
						tmp_misses = 1;
					seq_printf(m, "%-8s %-20llu %-20llu %-7lu %-7lu %u\n",
					       get_switch_target_name(name, j),
					       device_p->fd_cache_hits[j], device_p->fd_cache_misses[j],
					       rsbac_list_lol_count(device_p->fd_cache_handle[j]),
					       rsbac_list_lol_all_subcount(device_p->fd_cache_handle[j]),
					       ((__u32) tmp_hits)/((__u32) tmp_misses));
				}
			}
			if (header_shown)
				seq_printf(m, "%u fd_cache_invalidates, %u fd_cache_invalidate_alls\n",
					device_p->fd_cache_invalidates, device_p->fd_cache_invalidate_alls);
			device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	seq_printf(m, "\n%u delayed_kfree items in use, %lu delayed_kfree calls counted\n",
		delayed_kfree_used, delayed_kfree_count);
#endif
	seq_printf(m, "\nunion rsbac_attribute_value_t size is %zu\n",
		sizeof(union rsbac_attribute_value_t));
	return 0;
}

static int xstats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, xstats_proc_show, NULL);
}

static const struct proc_ops xstats_proc_ops = {
       .proc_open           = xstats_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *xstats;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE)
static int
auto_write_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		    "RSBAC auto write settings\n-------------------------\n");
	seq_printf(m,
		    "auto interval %u jiffies (%i jiffies = 1 second)\n",
		    auto_interval, HZ);

#ifdef CONFIG_RSBAC_DEBUG
	seq_printf(m, "debug level is %i\n",
		       rsbac_debug_auto);
#endif

	return 0;
}

static int auto_write_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, auto_write_proc_show, NULL);
}

static ssize_t auto_write_proc_write(struct file *file,
				 const char __user * buf, size_t count,
				 loff_t *data)
{
	ssize_t err;
	char *k_buf;
	char *p;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (count > PROC_BLOCK_SIZE) {
		return -EOVERFLOW;
	}

	if (!(k_buf = (char *) __get_free_page(GFP_KERNEL)))
		return -ENOMEM;
	err = copy_from_user(k_buf, buf, count);
	if (err < 0)
		return err;

	err = count;
	if (count < 13 || strncmp("auto", k_buf, 4)) {
		goto out;
	}
	if (!rsbac_initialized) {
		err = -ENOSYS;
		goto out;
	}
	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		err = -EPERM;
		goto out;
	}

	/*
	 * Usage: echo "auto interval #N" > /proc/rsbac_info/auto_write
	 *   to set auto_interval to given value
	 */
	if (!strncmp("interval", k_buf + 5, 8)) {
		unsigned int interval;

		p = k_buf + 5 + 9;

		if (*p == '\0')
			goto out;

		interval = simple_strtoul(p, NULL, 0);
		/* only accept minimum of 1 second */
		if (interval >= HZ) {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): setting auto write interval to %u\n",
				     interval);
			auto_interval = interval;
			err = count;
			goto out;
		} else {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): rejecting too short auto write interval %u (min. %i)\n",
				     interval, HZ);
			goto out;
		}
	}
#ifdef CONFIG_RSBAC_DEBUG
	/*
	 * Usage: echo "auto debug #N" > /proc/rsbac_info/auto_write
	 *   to set rsbac_debug_auto to given value
	 */
	if (!strncmp("debug", k_buf + 5, 5)) {
		unsigned int debug_level;

		p = k_buf + 5 + 6;

		if (*p == '\0')
			goto out;

		debug_level = simple_strtoul(p, NULL, 0);
		/* only accept 0 or 1 */
		if (!debug_level || (debug_level == 1)) {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): setting rsbac_debug_auto to %u\n",
				     debug_level);
			rsbac_debug_auto = debug_level;
			err = count;
		} else {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): rejecting invalid debug level (should be 0 or 1)\n");
		}
	}
#endif

      out:
	free_page((ulong) k_buf);
	return err;
}

static const struct proc_ops auto_write_proc_ops = {
       .proc_open           = auto_write_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
       .proc_write          = auto_write_proc_write,
};

static struct proc_dir_entry *auto_write;
#endif				/* CONFIG_RSBAC_AUTO_WRITE */

static int
versions_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		      "RSBAC version settings (%s)\n----------------------\n",
		      RSBAC_VERSION);
	seq_printf(m,
		    "Device list head size is %u, hash size is %lu\n",
		    (int) sizeof(struct rsbac_device_list_item_t),
		    BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS));
	seq_printf(m,
		    "FD lists:\nGEN  aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_GEN_FD_ACI_VERSION,
		    sizeof(struct rsbac_gen_fd_aci_t),
		    BIT(gen_nr_fd_hash_bits));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_MAC_FD_ACI_VERSION,
		    sizeof(struct rsbac_mac_fd_aci_t),
		    BIT(mac_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_FF)
	seq_printf(m,
		    "FF   aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_FF_FD_ACI_VERSION, sizeof(rsbac_ff_flags_t),
		    BIT(ff_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_RC_FD_ACI_VERSION,
		    sizeof(struct rsbac_rc_fd_aci_t),
		    BIT(rc_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_AUTH_FD_ACI_VERSION,
		    sizeof(struct rsbac_auth_fd_aci_t),
		    BIT(auth_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP  aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_CAP_FD_ACI_VERSION,
		    sizeof(struct rsbac_cap_fd_aci_t),
		    BIT(cap_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_RES)
	seq_printf(m,
		    "RES  aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_RES_FD_ACI_VERSION,
		    sizeof(struct rsbac_res_fd_aci_t),
		    BIT(res_nr_fd_hash_bits));
#endif
#if defined(CONFIG_RSBAC_UDF)
	seq_printf(m,
		    "UDF  aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_UDF_FD_ACI_VERSION,
		    sizeof(struct rsbac_udf_fd_aci_t),
		    BIT(udf_nr_fd_hash_bits));
#if defined(CONFIG_RSBAC_UDF_CACHE)
	seq_printf(m,
		    "UDFC aci version is %u, aci entry size is %zd, %lu lists per device\n",
		    RSBAC_UDF_CHECKED_FD_ACI_VERSION,
		    sizeof(rsbac_udf_checked_t),
		    BIT(udf_checked_nr_fd_hash_bits));
#endif
#endif
	seq_printf(m,
		    "\nDEV lists:\nGEN  aci version is %u, aci entry size is %zd\n",
		    RSBAC_GEN_DEV_ACI_VERSION,
		    sizeof(struct rsbac_gen_dev_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd\n",
		    RSBAC_MAC_DEV_ACI_VERSION,
		    sizeof(struct rsbac_mac_dev_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd\n",
		    RSBAC_RC_DEV_ACI_VERSION, sizeof(rsbac_rc_type_id_t));
#endif
	seq_printf(m, "\nIPC lists:\n");
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd\n",
		    RSBAC_MAC_IPC_ACI_VERSION,
		    sizeof(struct rsbac_mac_ipc_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd\n",
		    RSBAC_RC_IPC_ACI_VERSION, sizeof(rsbac_rc_type_id_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %zd\n",
		    RSBAC_JAIL_IPC_ACI_VERSION, sizeof(rsbac_jail_id_t));
#endif
	seq_printf(m,
		    "\nUSER lists:\nGEN  aci version is %u, aci entry size is %zd\n",
		    RSBAC_GEN_USER_ACI_VERSION,
		    sizeof(struct rsbac_gen_user_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd\n",
		    RSBAC_MAC_USER_ACI_VERSION,
		    sizeof(struct rsbac_mac_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd\n",
		    RSBAC_RC_USER_ACI_VERSION, sizeof(rsbac_rc_role_id_t));
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %zd\n",
		    RSBAC_AUTH_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP  aci version is %u, aci entry size is %zd\n",
		    RSBAC_CAP_USER_ACI_VERSION,
		    sizeof(struct rsbac_cap_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %zd\n",
		    RSBAC_JAIL_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_RES)
	seq_printf(m,
		    "RES aci version is %u, aci entry size is %zd\n",
		    RSBAC_RES_USER_ACI_VERSION,
		    sizeof(struct rsbac_res_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_UDF)
	seq_printf(m,
		    "UDF  aci version is %u, aci entry size is %zd\n",
		    RSBAC_UDF_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
	seq_printf(m,
		    "\nPROCESS lists:\nGEN  aci version is %i, aci entry size is %zd, default number of lists is %lu\n",
		    RSBAC_GEN_PROCESS_ACI_VERSION,
		    sizeof(rsbac_request_vector_t),
		    BIT(RSBAC_P_LIST_HASH_BITS));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd, default number of lists is %lu\n",
		    RSBAC_MAC_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_mac_process_aci_t),
		    BIT(RSBAC_P_LIST_HASH_BITS));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd, default number of lists is %lu\n",
		    RSBAC_RC_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_rc_process_aci_t),
		    BIT(RSBAC_P_LIST_HASH_BITS));
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %zd\n",
		    RSBAC_AUTH_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_auth_process_aci_t));
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP aci version is %u, aci entry size is %zd\n",
		    RSBAC_CAP_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_cap_process_aci_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %zd, number of lists is %lu\n",
		    RSBAC_JAIL_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_jail_process_aci_t),
		    BIT(RSBAC_P_LIST_HASH_BITS));
#endif

#if defined(CONFIG_RSBAC_NET_DEV)
	seq_printf(m, "\nNETDEV lists:\n");
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	seq_printf(m,
		    "GEN  aci version is %u, aci entry size is %zd\n",
		    RSBAC_GEN_NETDEV_ACI_VERSION,
		    sizeof(struct rsbac_gen_netdev_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd\n",
		    RSBAC_RC_NETDEV_ACI_VERSION,
		    sizeof(rsbac_rc_type_id_t));
#endif
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	seq_printf(m,
		    "\nNetwork Template list: version is %u, data size is %zd\n",
		    RSBAC_NET_TEMP_VERSION,
		    sizeof(struct rsbac_net_temp_data_t));
	seq_printf(m,
		    "\nNETOBJ lists:\nGEN  aci version is %u, aci entry size is %zd\n",
		    RSBAC_GEN_NETOBJ_ACI_VERSION,
		    sizeof(struct rsbac_gen_netobj_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %zd\n",
		    RSBAC_MAC_NETOBJ_ACI_VERSION,
		    sizeof(struct rsbac_mac_netobj_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %zd\n",
		    RSBAC_RC_NETOBJ_ACI_VERSION,
		    sizeof(rsbac_rc_type_id_t));
#endif
#endif
	seq_printf(m,
		    "\nlog_levels array: version is %u, array size is %zd\n",
		    RSBAC_LOG_LEVEL_VERSION,
		    R_NONE * (T_NONE + 1) * sizeof(rsbac_enum_t));
	seq_printf(m,
		    "\nattribute value union size is %u\n",
		    (int) sizeof(union rsbac_attribute_value_t));
#ifdef CONFIG_RSBAC_FD_CACHE
	seq_printf(m,
		    "fd cache attribute value union size is %u\n",
		    (int) sizeof(union rsbac_attribute_value_cache_t));
#endif
	return 0;
}

static int versions_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, versions_proc_show, NULL);
}

static const struct proc_ops versions_proc_ops = {
       .proc_open           = versions_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *versions;

#ifdef CONFIG_RSBAC_NET_OBJ
static int
net_temp_proc_show(struct seq_file *m, void *v)
{
	rsbac_net_temp_id_t *temp_array;
	long count;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "Network Templates\n-----------------\n");
	count =
	    rsbac_list_get_all_desc(net_temp_handle,
				    (void **) &temp_array);
	if (count > 0) {
		__u32 i;
		struct rsbac_net_temp_data_t data;

		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (net_temp_handle, &temp_array[i], &data)) {
				seq_printf(m, "%10u  %s\n",
					    temp_array[i], data.name);
				}
			}
		rsbac_kfree(temp_array);
	}
	seq_printf(m, "%lu templates\n", count);
	return 0;
}

static int net_temp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, net_temp_proc_show, NULL);
}

static const struct proc_ops net_temp_proc_ops = {
       .proc_open           = net_temp_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *net_temp;
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_JAIL
static int
jails_proc_show(struct seq_file *m, void *v)
{
	rsbac_pid_t *pid_array;
	struct rsbac_ipc_t *ipc_array;
	u_long count = 0;
	u_int i;
	struct rsbac_jail_process_aci_t data;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		    "Syslog-Jail is %u\n\nJAILed Processes\n----------------\nPID    Jail-ID    Flags   Max Caps   SCD get    SCD modify IP\n",
		    rsbac_jail_syslog_jail_id);

	count = rsbac_list_get_all_desc(process_handles.jail,
					(void **) &pid_array);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (process_handles.jail,
			     &pid_array[i], &data)) {
				seq_printf(m,
					    "%-5u  %-10u %-7u %-10llu %-10u %-10u %pI4\n",
					    pid_nr(pid_array[i]), data.id,
					    data.flags,
					    data.max_caps,
					    data.scd_get,
					    data.scd_modify,
					    &data.ip);
			}
		}
		rsbac_kfree(pid_array);
	}
	seq_printf(m, "%lu jailed processes\n", count);
	seq_printf(m,
		    "\nJAIL IPCs\n---------\nType        IPC-ID     Jail-ID\n");

	count =
	    rsbac_list_get_all_desc(ipc_handles.jail,
				    (void **) &ipc_array);
	if (count > 0) {
		__u32 i;
		rsbac_jail_id_t data;
		char tmp[RSBAC_MAXNAMELEN];

		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (ipc_handles.jail, &ipc_array[i], &data)) {
				seq_printf(m,
					    "%-10s  %-10lu %-10u\n",
					    get_ipc_target_name(tmp, ipc_array[i].type),
					    ipc_array[i].id.id_nr, data);
			}
		}
		rsbac_kfree(ipc_array);
	}
	seq_printf(m, "%lu JAIL IPCs\n", count);
	return 0;
}

static int jails_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jails_proc_show, NULL);
}

static const struct proc_ops jails_proc_ops = {
       .proc_open           = jails_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *jails;

#endif				/* JAIL */

static int register_all_rsbac_proc(void)
{
	proc_rsbac_root_p = proc_mkdir_mode("rsbac-info",
					      S_IFDIR | S_IRUGO | S_IXUGO,
					      NULL);
	if (!proc_rsbac_root_p)
		return -RSBAC_ECOULDNOTADDITEM;

	proc_rsbac_backup_p = proc_mkdir_mode("backup",
						S_IFDIR | S_IRUGO |
						S_IXUGO,
						proc_rsbac_root_p);
	if (!proc_rsbac_backup_p)
		return -RSBAC_ECOULDNOTADDITEM;

	devices = proc_create("devices",  S_IFREG | S_IRUGO, proc_rsbac_root_p, &devices_proc_ops);
	stats = proc_create("stats", S_IFREG | S_IRUGO, proc_rsbac_root_p, &stats_proc_ops);
	active = proc_create("active", S_IFREG | S_IRUGO, proc_rsbac_root_p, &active_proc_ops);
#ifdef CONFIG_RSBAC_XSTATS
	xstats = proc_create("xstats", S_IFREG | S_IRUGO, proc_rsbac_root_p, &xstats_proc_ops);
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	auto_write = proc_create("auto_write", S_IFREG | S_IRUGO | S_IWUGO, proc_rsbac_root_p, &auto_write_proc_ops);
#endif
	versions = proc_create("versions", S_IFREG | S_IRUGO, proc_rsbac_root_p, &versions_proc_ops);
#ifdef CONFIG_RSBAC_NET_OBJ
	net_temp = proc_create("net_temp", S_IFREG | S_IRUGO, proc_rsbac_root_p, &net_temp_proc_ops);
#endif
#ifdef CONFIG_RSBAC_JAIL
	jails = proc_create("jails", S_IFREG | S_IRUGO, proc_rsbac_root_p, &jails_proc_ops);
#endif

	return 0;
}

#endif // PROC

/************************************************* */
/*               RSBAC daemon                      */
/************************************************* */

/************************************************************************** */
/* Initialization, including ACI restoration for root device from disk.     */
/* After this call, all ACI is kept in memory for performance reasons,      */
/* but user and file/dir object ACI are written to disk on every change.    */

/* Since there can be no access to aci data structures before init,         */
/* rsbac_do_init() will initialize all rw-spinlocks to unlocked.               */

#if defined(CONFIG_RSBAC_AUTO_WRITE)
static void walk_delayed_kfree(void)
{
	struct rsbac_delayed_kfree_list_t * item;
	struct rsbac_delayed_kfree_list_t * last_item;
	struct rsbac_delayed_kfree_list_t * next_item;
	rsbac_time_t now = RSBAC_CURRENT_TIME;
#ifdef CONFIG_RSBAC_XSTATS
	u_int tmp_delayed_kfree_used;
#endif
//	u_int count = 0;

	spin_lock(&delayed_kfree_lock);
	item = delayed_kfree_first;
	last_item = delayed_kfree_last;
	delayed_kfree_first = delayed_kfree_last = NULL;
#ifdef CONFIG_RSBAC_XSTATS
	tmp_delayed_kfree_used = delayed_kfree_used;
	delayed_kfree_used = 0;
#endif
	spin_unlock(&delayed_kfree_lock);

	while (item && (item->max_age < now)) {
		next_item = item->next;
		rsbac_kfree(item->data);
		rsbac_sfree(delayed_kfree_item_slab, item);
		item = next_item;
#ifdef CONFIG_RSBAC_XSTATS
		tmp_delayed_kfree_used--;
#endif
//		count++;
	}
	if (item) {
//		rsbac_printk(KERN_DEBUG "walk_delayed_kfree() kfree'd %u items at %u, next is at %u\n", count, now, item->max_age);
		spin_lock(&delayed_kfree_lock);
		if (delayed_kfree_first) {
			last_item->next = delayed_kfree_first;
			delayed_kfree_first = item;
		} else {
			delayed_kfree_first = item;
			delayed_kfree_last = last_item;
		}
#ifdef CONFIG_RSBAC_XSTATS
		delayed_kfree_used += tmp_delayed_kfree_used;
#endif
		spin_unlock(&delayed_kfree_lock);
//	} else if (count) {
//		rsbac_printk(KERN_DEBUG "walk_delayed_kfree() kfree'd all %u items at %u\n", count, now);
	}
}
#endif

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_dev_lists(void)
#else
static int __init register_dev_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering DEV lists\n");
	{
		struct rsbac_gen_dev_aci_t def_aci = DEFAULT_GEN_DEV_ACI;

		list_info_p->version = RSBAC_GEN_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_dev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.gen, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  gen_dev_get_conv, &def_aci,
					  RSBAC_GEN_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV General");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_dev_aci_t def_aci = DEFAULT_MAC_DEV_ACI;

		list_info_p->version = RSBAC_MAC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_dev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.mac, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  mac_dev_get_conv, &def_aci,
					  RSBAC_MAC_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_major_aci = RSBAC_RC_GENERAL_TYPE;
		rsbac_rc_type_id_t def_aci = RC_type_inherit_parent;

		list_info_p->version = RSBAC_RC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_major_handles.rc,
					  list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_major_compare,
					  rc_dev_get_conv, &def_major_aci,
					  RSBAC_RC_ACI_DEV_MAJOR_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV major RC");
		}
		list_info_p->version = RSBAC_RC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  rc_dev_get_conv, &def_aci,
					  RSBAC_RC_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_ipc_lists(void)
#else
static int __init register_ipc_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering IPC lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_ipc_aci_t def_aci = DEFAULT_MAC_IPC_ACI;

		list_info_p->version = RSBAC_MAC_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_ipc_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.mac,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_RC_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.rc,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC RC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_JAIL)
	{
		rsbac_jail_id_t def_aci = RSBAC_JAIL_DEF_ID;

		list_info_p->version = RSBAC_JAIL_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size = sizeof(rsbac_jail_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.jail,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_JAIL_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC JAIL");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_user_lists1(void)
#else
static int __init register_user_lists1(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering USER lists\n");
	{
		struct rsbac_gen_user_aci_t def_aci = DEFAULT_GEN_U_ACI;

		list_info_p->version = RSBAC_GEN_USER_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.gen, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  gen_user_get_conv,
					  &def_aci,
					  RSBAC_GEN_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER General");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_user_aci_t def_aci = DEFAULT_MAC_U_ACI;

		list_info_p->version = RSBAC_MAC_USER_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.mac, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  mac_user_get_conv, &def_aci,
					  RSBAC_MAC_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER MAC");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.mac)) {
			struct rsbac_mac_user_aci_t sysadm_aci =
			    DEFAULT_MAC_U_SYSADM_ACI;
			struct rsbac_mac_user_aci_t secoff_aci =
			    DEFAULT_MAC_U_SECOFF_ACI;
			struct rsbac_mac_user_aci_t auditor_aci =
			    DEFAULT_MAC_U_AUDITOR_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER MAC ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER MAC entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER MAC entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER MAC entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_FF)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_FF_USER_ACI_VERSION;
		list_info_p->key = RSBAC_FF_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.ff, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST | RSBAC_LIST_DEF_DATA,
					  NULL,
					  ff_user_get_conv,
					  &def_aci, RSBAC_FF_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER FF");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.ff)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER FF ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER FF entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER FF entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			role = SR_auditor;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER FF entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_user_aci_t def_aci = DEFAULT_CAP_U_ACI;

		list_info_p->version = RSBAC_CAP_USER_ACI_VERSION;
		list_info_p->key = RSBAC_CAP_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_cap_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.cap, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, 
					  cap_user_get_conv,
					  &def_aci,
					  RSBAC_CAP_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER CAP");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.cap)) {
			struct rsbac_cap_user_aci_t sysadm_aci =
			    DEFAULT_CAP_U_SYSADM_ACI;
			struct rsbac_cap_user_aci_t secoff_aci =
			    DEFAULT_CAP_U_SECOFF_ACI;
			struct rsbac_cap_user_aci_t auditor_aci =
			    DEFAULT_CAP_U_AUDITOR_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER CAP ACI could not be read - generating standard entries!\n");
			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER CAP ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER CAP entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER CAP entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER CAP entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_UDF)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_UDF_USER_ACI_VERSION;
		list_info_p->key = RSBAC_UDF_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.udf, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST | RSBAC_LIST_DEF_DATA,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_UDF_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER UDF");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.udf)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER UDF ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add(user_handles.udf, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER UDF entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add(user_handles.udf, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER UDF entry could not be added!\n");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_user_lists2(void)
#else
static int __init register_user_lists2(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}

#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_user_aci_t def_aci = DEFAULT_RC_U_ACI;

		list_info_p->version = RSBAC_RC_USER_ACI_VERSION;
		list_info_p->key = RSBAC_RC_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  rc_user_get_conv, &def_aci,
					  RSBAC_RC_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER RC");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.rc)) {
			rsbac_uid_t user;
			struct rsbac_rc_user_aci_t sysadm_aci =
			    DEFAULT_RC_U_SYSADM_ACI;
			struct rsbac_rc_user_aci_t secoff_aci =
			    DEFAULT_RC_U_SECOFF_ACI;
			struct rsbac_rc_user_aci_t auditor_aci =
			    DEFAULT_RC_U_AUDITOR_ACI;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER RC ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER RC entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER RC entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER RC entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_AUTH)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_AUTH_USER_ACI_VERSION;
		list_info_p->key = RSBAC_AUTH_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.auth, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST,
					  NULL,
					  auth_user_get_conv,
					  &def_aci,
					  RSBAC_AUTH_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER AUTH");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.auth)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER AUTH ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER AUTH entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER AUTH entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			role = SR_auditor;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER AUTH entry could not be added!\n");
		}
	}
#endif				/* AUTH */
#if defined(CONFIG_RSBAC_JAIL)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_JAIL_USER_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.jail, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST,
					  NULL,
					  jail_user_get_conv,
					  &def_aci,
					  RSBAC_JAIL_ACI_USER_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER JAIL");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.jail)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER JAIL ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add
			    (user_handles.jail, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER JAIL entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add
			    (user_handles.jail, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER JAIL entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RES)
	{
		struct rsbac_list_lol_info_t *list_lol_info_p;
		rsbac_system_role_int_t def_value;
		int tmperr;

		list_lol_info_p = rsbac_kmalloc_unlocked(sizeof(*list_lol_info_p));
		if (!list_lol_info_p) {
			err = -ENOMEM;
			goto skip;
		}
		list_lol_info_p->version = RSBAC_RES_USER_ACI_VERSION;
		list_lol_info_p->key = RSBAC_RES_USER_ACI_KEY;
		list_lol_info_p->desc_size = sizeof(rsbac_uid_t);
		list_lol_info_p->data_size = 0;
		list_lol_info_p->subdesc_size = sizeof(rsbac_res_desc_t);
		list_lol_info_p->subdata_size = sizeof(rsbac_res_limit_t);
		list_lol_info_p->max_age = 0;

		tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				&user_handles.res_min,
				list_lol_info_p,
				RSBAC_LIST_PERSIST | \
				RSBAC_LIST_OWN_SLAB | \
				RSBAC_LIST_DEF_DATA | \
					RSBAC_LIST_AUTO_HASH_RESIZE,
				NULL, /* compare */
				NULL, /* subcompare */
				NULL, NULL, /* get_conv */
				NULL, NULL, /* def data */
				RSBAC_RES_ACI_USER_MIN_NAME,
				RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
				1,
				rsbac_list_hash_uid,
				NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_user_lists2(): registering RES list of lists %s for users failed with error %s!\n",
					     RSBAC_RES_ACI_USER_MIN_NAME,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		} else {
			if (rsbac_list_lol_count(user_handles.res_min) == 0) {
				rsbac_list_handle_t old_res_handle;

#if 0
				rsbac_printk(KERN_DEBUG "register_user_lists2(): RES list of lists %s for users is empty, try to fill from old RES list %s!\n",
					     RSBAC_RES_ACI_USER_MIN_NAME,
					     RSBAC_RES_OLD_ACI_USER_NAME);
#endif
				list_info_p->version = RSBAC_RES_USER_ACI_VERSION;
				list_info_p->key = RSBAC_RES_USER_ACI_KEY;
				list_info_p->desc_size = sizeof(rsbac_uid_t);
				list_info_p->data_size = sizeof(struct rsbac_res_old_user_aci_t);
				list_info_p->max_age = 0;
				tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
								&old_res_handle,
								list_info_p,
								RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST,
								NULL,
								res_user_get_conv,
								NULL,
								RSBAC_RES_OLD_ACI_USER_NAME,
								RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
								1,
								rsbac_list_hash_uid,
								NULL);
				if (tmperr) {
					char *tmp;

					tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
					if (tmp) {
						rsbac_printk(KERN_WARNING "register_user_lists2(): registering old RES list %s for users failed with error %s!\n",
							     RSBAC_RES_OLD_ACI_USER_NAME,
							     get_error_name(tmp,
									    tmperr));
						rsbac_kfree(tmp);
					}
				} else {
					char * array_p;
					rsbac_time_t * ttl_p;
					long item_count;

					item_count = rsbac_list_get_all_items_ttl(old_res_handle, (void **) &array_p, &ttl_p);
					if (item_count > 0) {
						char *tmp = array_p;
						int size = rsbac_list_get_item_size(old_res_handle);
						int i;
						rsbac_res_desc_t res_num;
						rsbac_res_limit_t res_value;
						int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);
						rsbac_boolean_t all_zero;

						for (i = 0; i < item_count; i++) {
							all_zero = TRUE;
							for(res_num = 0; res_num <= maxval ; res_num++) {
								res_value = ( (struct rsbac_res_old_user_aci_t *) (tmp + list_info_p->desc_size) )->res_min[res_num];
								if (res_value != 0)
									all_zero = FALSE;
							}
							if (!all_zero) {
								for(res_num = 0; res_num <= maxval ; res_num++) {
									res_value = ( (struct rsbac_res_old_user_aci_t *) (tmp + list_info_p->desc_size) )->res_min[res_num];
									rsbac_ta_list_lol_subadd_ttl(0,
												user_handles.res_min, ttl_p[i],
												tmp, &res_num,
												&res_value);
								}
							}
							tmp += size;
						}
						rsbac_kfree(array_p);
						rsbac_kfree(ttl_p);
					}
					rsbac_list_detach(&old_res_handle, RSBAC_RES_USER_ACI_KEY);
#if 0
					rsbac_printk(KERN_DEBUG "register_user_lists(): RES list of lists %s got %lu items from old RES list %s!\n",
						     RSBAC_RES_ACI_USER_MIN_NAME,
						     item_count,
						     RSBAC_RES_OLD_ACI_USER_NAME);
#endif
				}
			}
		}

		list_lol_info_p->version = RSBAC_RES_USER_ACI_VERSION;
		list_lol_info_p->key = RSBAC_RES_USER_ACI_KEY;
		list_lol_info_p->desc_size = sizeof(rsbac_uid_t);
		list_lol_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_lol_info_p->subdesc_size = sizeof(rsbac_res_desc_t);
		list_lol_info_p->subdata_size = sizeof(rsbac_res_limit_t);
		list_lol_info_p->max_age = 0;
		def_value = SR_user;

		tmperr = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				&user_handles.res_max,
				list_lol_info_p,
				RSBAC_LIST_PERSIST | \
				RSBAC_LIST_OWN_SLAB | \
				RSBAC_LIST_DEF_DATA | \
					RSBAC_LIST_AUTO_HASH_RESIZE,
				NULL, /* compare */
				NULL, /* subcompare */
				NULL, NULL, /* get_conv */
				&def_value, NULL, /* def data */
				RSBAC_RES_ACI_USER_MAX_NAME,
				RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
				1,
				rsbac_list_hash_uid,
				NULL);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_user_lists2(): registering RES list of lists %s for users failed with error %s!\n",
					     RSBAC_RES_ACI_USER_MAX_NAME,
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		} else {
			if (rsbac_list_lol_count(user_handles.res_max) == 0) {
				rsbac_list_handle_t old_res_handle;

#if 0
				rsbac_printk(KERN_DEBUG "register_user_lists2(): RES list of lists %s for users is empty, try to fill from old RES list %s!\n",
					     RSBAC_RES_ACI_USER_MAX_NAME,
					     RSBAC_RES_OLD_ACI_USER_NAME);
#endif
				list_info_p->version = RSBAC_RES_USER_ACI_VERSION;
				list_info_p->key = RSBAC_RES_USER_ACI_KEY;
				list_info_p->desc_size = sizeof(rsbac_uid_t);
				list_info_p->data_size = sizeof(struct rsbac_res_old_user_aci_t);
				list_info_p->max_age = 0;
				tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
								&old_res_handle,
								list_info_p,
								RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_PERSIST,
								NULL,
								res_user_get_conv,
								NULL,
								RSBAC_RES_OLD_ACI_USER_NAME,
								RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
								1,
								rsbac_list_hash_uid,
								NULL);
				if (tmperr) {
					char *tmp;

					tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
					if (tmp) {
						rsbac_printk(KERN_WARNING "register_user_lists2(): registering old RES list %s for users failed with error %s!\n",
							     RSBAC_RES_OLD_ACI_USER_NAME,
							     get_error_name(tmp,
									    tmperr));
						rsbac_kfree(tmp);
					}
				} else {
					char * array_p;
					rsbac_time_t * ttl_p;
					long item_count;

					item_count = rsbac_list_get_all_items_ttl(old_res_handle, (void **) &array_p, &ttl_p);
					if (item_count > 0) {
						char *tmp = array_p;
						int size = rsbac_list_get_item_size(old_res_handle);
						int i;
						rsbac_res_desc_t res_num;
						rsbac_res_limit_t res_value;
						int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);
						rsbac_boolean_t all_zero;

						for (i = 0; i < item_count; i++) {
							rsbac_ta_list_lol_add_ttl(0,
										user_handles.res_max, ttl_p[i],
										tmp,
										&( (struct rsbac_res_old_user_aci_t *) (tmp + list_info_p->desc_size) )->res_role);
							all_zero = TRUE;
							for(res_num = 0; res_num <= maxval ; res_num++) {
								res_value = ( (struct rsbac_res_old_user_aci_t *) (tmp + list_info_p->desc_size) )->res_max[res_num];
								if (res_value != 0)
									all_zero = FALSE;
							}
							if (!all_zero) {
								for(res_num = 0; res_num <= maxval ; res_num++) {
									res_value = ( (struct rsbac_res_old_user_aci_t *) (tmp + list_info_p->desc_size) )->res_max[res_num];
									rsbac_ta_list_lol_subadd_ttl(0,
												user_handles.res_max, ttl_p[i],
												tmp, &res_num,
												&res_value);
								}
							}
							tmp += size;
						}
						rsbac_kfree(array_p);
						rsbac_kfree(ttl_p);
					}
					rsbac_list_detach(&old_res_handle, RSBAC_RES_USER_ACI_KEY);
					rsbac_printk(KERN_DEBUG "register_user_lists(): RES list of lists %s got %lu items from old RES list %s!\n",
						     RSBAC_RES_ACI_USER_MAX_NAME,
						     item_count,
						     RSBAC_RES_OLD_ACI_USER_NAME);
				}
			}
			if (!rsbac_no_defaults && !rsbac_list_lol_count(user_handles.res_max)) {
				rsbac_uid_t user;
				rsbac_system_role_int_t res_role;

				rsbac_printk(KERN_WARNING "rsbac_do_init(): USER RES ACI could not be read - generating standard entries!\n");
				user = RSBAC_SYSADM_UID;
				res_role = SR_administrator;
				if (rsbac_list_lol_add(user_handles.res_max, &user, &res_role))
					rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER RES entry could not be added!\n");
				user = RSBAC_SECOFF_UID;
				res_role = SR_security_officer;
				if (rsbac_list_lol_add(user_handles.res_max, &user, &res_role))
					rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER RES entry could not be added!\n");
			}
		}
		rsbac_kfree(list_lol_info_p);
	}
skip:
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_process_lists(void)
#else
static int __init register_process_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering PROCESS lists\n");
	{
		struct rsbac_gen_process_aci_t def_aci = DEFAULT_GEN_P_ACI;

		list_info_p->version = RSBAC_GEN_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_process_aci_t);
		list_info_p->max_age = 0;
		gen_nr_p_hash_bits = RSBAC_P_LIST_HASH_BITS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.gen,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_GEN_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
						gen_nr_p_hash_bits,
						rsbac_list_hash_pid,
						NULL);
		if (err) {
			registration_error(err, "PROCESS GEN");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_process_aci_t def_aci = DEFAULT_MAC_P_ACI;

		list_info_p->version = RSBAC_MAC_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_process_aci_t);
		list_info_p->max_age = 0;
		mac_nr_p_hash_bits = RSBAC_P_LIST_HASH_BITS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.mac,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_MAC_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
						mac_nr_p_hash_bits,
						rsbac_list_hash_pid,
						NULL);
		if (err) {
			registration_error(err, "PROCESS MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_process_aci_t def_aci = DEFAULT_RC_P_ACI;

		list_info_p->version = RSBAC_RC_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_RC_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_process_aci_t);
		list_info_p->max_age = 0;
		rc_nr_p_hash_bits = RSBAC_P_LIST_HASH_BITS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.rc,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_RC_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
						rc_nr_p_hash_bits,
						rsbac_list_hash_pid,
						NULL);
		if (err) {
			registration_error(err, "PROCESS RC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_AUTH)
	{
		struct rsbac_auth_process_aci_t def_aci = DEFAULT_AUTH_P_ACI;

		list_info_p->version = RSBAC_AUTH_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_AUTH_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_auth_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.auth,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_AUTH_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
#if defined(CONFIG_RSBAC_AUTH_LEARN)
					  RSBAC_LIST_MIN_MAX_HASH_BITS,
#else
					  1,
#endif
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS AUTH");
		}
	}
#endif
#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_process_aci_t def_aci = DEFAULT_CAP_P_ACI;

		list_info_p->version = RSBAC_CAP_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_CAP_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_cap_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.cap,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_CAP_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS CAP");
		}
	}
#endif
#if defined(CONFIG_RSBAC_JAIL)
	{
		struct rsbac_jail_process_aci_t def_aci =
		    DEFAULT_JAIL_P_ACI;

		list_info_p->version = RSBAC_JAIL_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_jail_process_aci_t);
		list_info_p->max_age = 0;
		jail_nr_p_hash_bits = RSBAC_P_LIST_HASH_BITS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.jail,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_JAIL_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
						jail_nr_p_hash_bits,
						rsbac_list_hash_pid,
						NULL);
		if (err) {
			registration_error(err, "PROCESS JAIL");
		}
	}
#endif
#if defined(CONFIG_RSBAC_UDF)
	{
		struct rsbac_udf_process_aci_t def_aci = DEFAULT_UDF_P_ACI;

		list_info_p->version = RSBAC_UDF_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_UDF_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_udf_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.udf,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_UDF_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS UDF");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_UM
#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_group_lists(void)
#else
static int __init register_group_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering GROUP lists\n");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_GROUP_ACI_VERSION;
		list_info_p->key = RSBAC_RC_GROUP_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_gid_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &group_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_RC_ACI_GROUP_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_gid,
					  NULL);
		if (err) {
			registration_error(err, "GROUP RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* UM */

#ifdef CONFIG_RSBAC_NET_DEV
#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_netdev_lists(void)
#else
static int __init register_netdev_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering NETDEV lists\n");
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	{
		struct rsbac_gen_netdev_aci_t def_aci =
		    DEFAULT_GEN_NETDEV_ACI;

		list_info_p->version = RSBAC_GEN_NETDEV_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_NETDEV_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_netdev_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_netdev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &netdev_handles.gen,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA,
					  netdev_compare, NULL, &def_aci,
					  RSBAC_GEN_ACI_NETDEV_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM);
		if (err) {
			registration_error(err, "NETDEV General");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETDEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETDEV_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_netdev_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &netdev_handles.rc,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA,
					  netdev_compare, NULL, &def_aci,
					  RSBAC_RC_ACI_NETDEV_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM);
		if (err) {
			registration_error(err, "NETDEV RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* NET_DEV */

#ifdef CONFIG_RSBAC_NET_OBJ
#ifdef CONFIG_RSBAC_INIT_DELAY
static void fill_default_nettemp(void)
#else
static void __init fill_default_nettemp(void)
#endif
{
	rsbac_net_temp_id_t id;
	struct rsbac_net_temp_data_t data;

	id = RSBAC_NET_TEMP_LNET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Localnet");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 8;
	rsbac_net_str_to_inet(RSBAC_NET_TEMP_LNET_ADDRESS,
			      &data.address.inet.addr[0]);
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_LAN_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Internal LAN");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 16;
	rsbac_net_str_to_inet(RSBAC_NET_TEMP_LAN_ADDRESS,
			      &data.address.inet.addr[0]);
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_AUTO_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Auto-IPv4");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 32;
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_INET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "AF_INET");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 0;
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_INET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = RSBAC_NET_ANY;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "ALL");
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_nettemp_list(void)
#else
static int __init register_nettemp_list(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering network template list\n");
	list_info_p->version = RSBAC_NET_TEMP_VERSION;
	list_info_p->key = RSBAC_NET_TEMP_KEY;
	list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
	list_info_p->data_size = sizeof(struct rsbac_net_temp_data_t);
	list_info_p->max_age = 0;
	err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
				  &net_temp_handle,
				  list_info_p,
				  RSBAC_LIST_BACKUP |
				  RSBAC_LIST_PERSIST,
				  rsbac_list_compare_u32,
				  net_temp_get_conv,
				  NULL,
				  RSBAC_NET_TEMP_NAME,
				  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
				  0,
				  rsbac_list_hash_nettemp,
				  NULL);
	if (err) {
		registration_error(err, "Network Template");
	} else
	    if (!rsbac_no_defaults && !rsbac_list_count(net_temp_handle)) {
		rsbac_printk(KERN_WARNING "rsbac_do_init(): Network Templates could not be read - generating standard entries!\n");
		fill_default_nettemp();
	}
	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_nettemp_aci_lists(void)
#else
static int __init register_nettemp_aci_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering NETTEMP lists\n");
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	{
		list_info_p->version = RSBAC_GEN_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.gen,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_gen_netobj_aci,
					  RSBAC_GEN_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP GEN");
		}
	}
#endif
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.mac,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_nettemp_aci_t def_aci =
		    DEFAULT_RC_NETTEMP_ACI;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_nettemp_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.rc,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_RC_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_netobj_lists(void)
#else
static int __init register_netobj_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering local NETOBJ lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &lnetobj_handles.mac,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_LNETOBJ_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "LNETOBJ MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &lnetobj_handles.rc,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_LNETOBJ_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "LNETOBJ RC");
		}
	}
#endif
	rsbac_pr_debug(ds, "registering remote NETOBJ lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &rnetobj_handles.mac,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_RNETOBJ_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "RNETOBJ MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &rnetobj_handles.rc,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_RNETOBJ_NAME,
					  RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "RNETOBJ RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_INIT_DELAY
static int rsbac_do_init(void)
#else
static int __init rsbac_do_init(void)
#endif
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	struct rsbac_device_list_item_t *new_device_p;
	struct rsbac_list_info_t *list_info_p;
	struct vfsmount *vfsmount_p;
	u_int i;

	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());

#if defined(CONFIG_RSBAC_AUTO_WRITE)
	delayed_kfree_item_slab = rsbac_slab_create("rsbac_delayed_kfree",
					sizeof(struct rsbac_delayed_kfree_list_t));
	if (!delayed_kfree_item_slab)
		rsbac_printk(KERN_WARNING "rsbac_do_init(): Failed to create rsbac_delayed_kfree slab\n");
#endif
	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
#ifdef CONFIG_RSBAC_INIT_DELAY
	if (rsbac_root_vfsmount_p)
		vfsmount_p = rsbac_root_vfsmount_p;
	else
#endif
	{
		write_seqlock(&current->fs->seq);
		vfsmount_p = mntget(current->fs->root.mnt);
		write_sequnlock(&current->fs->seq);
	}
	compiled_modules[0] = (char) 0;
#ifdef CONFIG_RSBAC_REG
	strcat(compiled_modules, " REG");
#endif
#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_MAC_LIGHT
	strcat(compiled_modules, " MAC-L");
#else
	strcat(compiled_modules, " MAC");
#endif
#endif
#ifdef CONFIG_RSBAC_FF
	strcat(compiled_modules, " FF");
#endif
#ifdef CONFIG_RSBAC_RC
	strcat(compiled_modules, " RC");
#endif
#ifdef CONFIG_RSBAC_AUTH
	strcat(compiled_modules, " AUTH");
#endif
#ifdef CONFIG_RSBAC_ACL
	strcat(compiled_modules, " ACL");
#endif
#ifdef CONFIG_RSBAC_CAP
	strcat(compiled_modules, " CAP");
#endif
#ifdef CONFIG_RSBAC_JAIL
	strcat(compiled_modules, " JAIL");
#endif
#ifdef CONFIG_RSBAC_RES
	strcat(compiled_modules, " RES");
#endif
	rsbac_printk(KERN_INFO "rsbac_do_init(): Initializing RSBAC %s on device %02u:%02u\n",
		     RSBAC_VERSION,
		     RSBAC_MAJOR(vfsmount_p->mnt_sb->s_dev),
		     RSBAC_MINOR(vfsmount_p->mnt_sb->s_dev));
	/* Print banner we are initializing */
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
	if (rsbac_nosyslog)
#endif
		printk(KERN_INFO
		       "rsbac_do_init(): Initializing RSBAC %s\n",
		       RSBAC_VERSION);

	rsbac_printk(KERN_INFO "rsbac_do_init(): compiled modules:%s\n",
		     compiled_modules);

	device_item_slab = rsbac_slab_create_rcu("rsbac_device_item",
			sizeof(struct rsbac_device_list_item_t));

#if defined(CONFIG_RSBAC_AUTO_WRITE)
	lockdep_set_class(&rsbac_write_lock, &rsbac_write_lock_class);
#endif
#if  defined(CONFIG_RSBAC_AUTO_WRITE) \
   || defined(CONFIG_RSBAC_INIT_THREAD) || defined(CONFIG_RSBAC_NO_WRITE)
	lockdep_set_class(&rsbac_mount_lock, &rsbac_mount_lock_class);
#endif
	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		device_head_p[i] = rsbac_kmalloc_clear_unlocked(sizeof(*device_head_p[i]));
		if (!device_head_p[i]) {
			rsbac_printk(KERN_WARNING
				"rsbac_do_init(): Failed to allocate device_list_heads[%s]\n", i);
			return -ENOMEM;
		}
		spin_lock_init(&device_list_locks[i]);
		init_srcu_struct(&device_list_srcu[i]);
		lockdep_set_class(&device_list_locks[i], &device_list_lock_class);
	}

#if defined(CONFIG_RSBAC_PROC)
	rsbac_pr_debug(stack, "free stack before registering proc dir: %lu\n",
		       rsbac_stack_free_space());
	rsbac_printk(KERN_INFO "rsbac_do_init(): Registering RSBAC proc dir\n");
	register_all_rsbac_proc();
#endif
	rsbac_pr_debug(stack, "free stack before get_super: %lu\n",
		       rsbac_stack_free_space());
	/* read fd aci from root device */
	rsbac_pr_debug(ds, "reading aci from device "
		       "number %02u:%02u\n",
		       rsbac_root_dev_major,
		       rsbac_root_dev_minor);
	/* create a private device item */
	new_device_p = create_device_item(vfsmount_p, RSBAC_MAJOR(vfsmount_p->mnt_sb->s_dev), RSBAC_MINOR(vfsmount_p->mnt_sb->s_dev));
	if (!new_device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_do_init(): Could not alloc device item!\n");
		err = -RSBAC_ECOULDNOTADDDEVICE;
		goto out;
	}
	/* Add new_device_p to device list */
	/* OK, go on */
	device_p = add_device_item(new_device_p, TRUE);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_do_init(): Could not add device!\n");
		clear_device_item(new_device_p);
		err = -RSBAC_ECOULDNOTADDDEVICE;
		goto out;
	}

	/* init lists - we need the root device_p to be initialized, but no generic list registered */
	rsbac_printk(KERN_INFO "rsbac_do_init(): Initializing generic lists\n");
	rsbac_list_init();

	rsbac_pr_debug(stack, "free stack before init_debug: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_debug();

	rsbac_printk(KERN_INFO "rsbac_do_init(): reading FD attributes from root dev\n");
	rsbac_pr_debug(stack, "free stack before reading FD lists: %lu\n",
		       rsbac_stack_free_space());

	/* no locking needed, device_p is known and there can be no parallel init! */
	if ((err = register_fd_lists(device_p, rsbac_root_dev_major, rsbac_root_dev_minor))) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): File/Dir lists registration failed for dev %02u:%02u, err %s!\n",
				     rsbac_root_dev_major, rsbac_root_dev_minor,
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#ifdef CONFIG_RSBAC_FD_CACHE
	if (rsbac_want_cache(device_p))
		register_fd_cache_lists(device_p);
#endif

	rsbac_pr_debug(stack, "free stack before DEV lists registration: %lu\n",
		       rsbac_stack_free_space());
	register_dev_lists();
	rsbac_pr_debug(stack, "free stack before registering IPC lists: %lu\n",
		       rsbac_stack_free_space());
	register_ipc_lists();
	rsbac_pr_debug(stack, "free stack before registering USER lists 1: %lu\n",
		       rsbac_stack_free_space());
	register_user_lists1();
	rsbac_pr_debug(stack, "free stack before registering USER lists 2: %lu\n",
		       rsbac_stack_free_space());
	register_user_lists2();
	rsbac_pr_debug(stack, "free stack before registering PROCESS aci: %lu\n",
		       rsbac_stack_free_space());
	register_process_lists();


#ifdef CONFIG_RSBAC_UM
	rsbac_pr_debug(stack, "free stack before GROUP lists registration: %lu\n",
		       rsbac_stack_free_space());
	register_group_lists();
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	register_netdev_lists();
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	register_nettemp_list();
	register_nettemp_aci_lists();
	register_netobj_lists();
#endif				/* NET_OBJ */

/* Call other init functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_pr_debug(stack, "free stack before init_mac: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_mac();
#endif

#if defined(CONFIG_RSBAC_RC)
	rsbac_pr_debug(stack, "free stack before init_rc: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_rc();
#endif

#if defined(CONFIG_RSBAC_AUTH)
	rsbac_pr_debug(stack, "free stack before init_auth: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_auth();
	if (rsbac_auth_enable_login) {
		struct dentry *t_dentry;
		struct dentry *dir_dentry = NULL;
		struct rsbac_auth_fd_aci_t auth_fd_aci =
		    DEFAULT_AUTH_FD_ACI;
		rsbac_old_inode_nr_t inode_nr;
		void * inode_nr_p;

		rsbac_printk(KERN_WARNING "rsbac_do_init(): auth_enable_login is set: setting auth_may_setuid for %s\n",
			     RSBAC_AUTH_LOGIN_PATH);

		/* lookup filename */
		if (vfsmount_p) {
			inode_lock(vfsmount_p->mnt_sb->s_root->d_inode);
			dir_dentry = lookup_one(&nop_mnt_idmap, &QSTR(RSBAC_AUTH_LOGIN_PATH_DIR),
						 vfsmount_p->mnt_sb->s_root);
			inode_unlock(vfsmount_p->mnt_sb->s_root->d_inode);
		}
		if (!dir_dentry) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR);
			goto auth_out;
		}
		if (IS_ERR(dir_dentry)) {
			err = PTR_ERR(dir_dentry);
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s returned %i\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR, err);
			goto auth_out;
		}
		if (!dir_dentry->d_inode) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR);
			dput(dir_dentry);
			goto auth_out;
		}

		inode_lock(dir_dentry->d_inode);
		t_dentry = lookup_one(&nop_mnt_idmap, &QSTR(RSBAC_AUTH_LOGIN_PATH_FILE),
						dir_dentry);
		inode_unlock(dir_dentry->d_inode);

		if (!t_dentry) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s/%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE);
			goto auth_out;
		}
		if (IS_ERR(t_dentry)) {
			err = PTR_ERR(t_dentry);
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s/%s returned %i\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE, err);
			goto auth_out;
		}
		if (!t_dentry->d_inode) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to lookup_one for /%s/%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE);
			dput(t_dentry);
			goto auth_out;
		}

		if (!t_dentry->d_inode) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): file %s not found\n",
				     RSBAC_AUTH_LOGIN_PATH);
			err = -RSBAC_EINVALIDTARGET;
			goto auth_out_dput;
		}
		/* is inode of type file? */
		if (!S_ISREG(t_dentry->d_inode->i_mode)) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): %s is no file\n",
				     RSBAC_AUTH_LOGIN_PATH);
			err = -RSBAC_EINVALIDTARGET;
			goto auth_out_dput;
		}
		if (device_p->persist) {
			inode_nr = t_dentry->d_inode->i_ino;
			inode_nr_p = &inode_nr;
		} else
			inode_nr_p = &t_dentry->d_inode->i_ino;
		rsbac_list_get_data(device_p->handles.auth,
				    inode_nr_p,
				    &auth_fd_aci);
		auth_fd_aci.auth_may_setuid = TRUE;
		if (rsbac_list_add(device_p->handles.auth, inode_nr_p, &auth_fd_aci)) {	/* Adding failed! */
			rsbac_printk(KERN_WARNING "rsbac_do_init(): Could not add AUTH file/dir item!\n");
			err = -RSBAC_ECOULDNOTADDITEM;
		}

	      auth_out_dput:
	      auth_out:
		{
		}
	}
#endif

#if defined(CONFIG_RSBAC_ACL)
	rsbac_pr_debug(stack, "free stack before init_acl: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_acl();
#endif

#if defined(CONFIG_RSBAC_UDF)
	rsbac_pr_debug(stack, "free stack before init_udf: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_udf();
#endif

#if defined(CONFIG_RSBAC_UM)
	rsbac_pr_debug(stack, "free stack before init_um: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_um();
#endif
	rsbac_pr_debug(stack, "free stack before init_adf: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_adf();

/* Tell that rsbac is initialized                                       */
	rsbac_allow_mounts = TRUE;

/* Add delayed mounts */
	if (rsbac_mount_list) {
		u_int hash;
		int srcu_idx;
		struct rsbac_mount_list_t * mount_p = rsbac_mount_list;
		__u32 major;
		__u32 minor;

		while (mount_p) {
			if (RSBAC_IS_INVALID_PTR(mount_p->vfsmount_p->mnt_sb))
				continue;
			major = RSBAC_MAJOR(mount_p->vfsmount_p->mnt_sb->s_dev);
			minor = RSBAC_MINOR(mount_p->vfsmount_p->mnt_sb->s_dev);
			if (!RSBAC_IS_INVALID_PTR(mount_p->vfsmount_parent_p)) {
				__u32 pmajor;
				__u32 pminor;

				pmajor = RSBAC_MAJOR(mount_p->vfsmount_parent_p->mnt_sb->s_dev);
				pminor = RSBAC_MINOR(mount_p->vfsmount_parent_p->mnt_sb->s_dev);
				hash = device_hash(pminor);
				srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
				device_p = lookup_device(pmajor, pminor, hash);
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				if(!device_p) {
					rsbac_printk(KERN_WARNING "rsbac_do_init(): while mounting delayed device %02u:%02u, fs-type %s, its parent device %02u:%02u, fs-type %s, is not mounted, forcing parent mount!\n",
						major,
						minor,
						mount_p->vfsmount_p->mnt_sb->s_type->name,
						pmajor, pminor,
						mount_p->vfsmount_parent_p->mnt_sb->s_type->name);
					rsbac_mount(mount_p->vfsmount_parent_p, NULL);
					mntput(mount_p->vfsmount_parent_p);
				} else {
					/* skip existing dev */
					mntput(mount_p->vfsmount_parent_p);
				}
			}
			hash = device_hash(minor);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(major, minor, hash);
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			if(!device_p) {
				rsbac_printk(KERN_INFO "rsbac_do_init(): mounting delayed device %02u:%02u, fs-type %s\n",
					major, minor,
					mount_p->vfsmount_p->mnt_sb->s_type->name);
				rsbac_mount(mount_p->vfsmount_p, NULL);
				if(mount_p->vfsmount_parent_p)
					mntput(mount_p->vfsmount_parent_p);
			} else {
				/* skip existing dev */
				mntput(mount_p->vfsmount_p);
				if(mount_p->vfsmount_parent_p)
					mntput(mount_p->vfsmount_parent_p);
			}
			rsbac_mount_list = mount_p;
			mount_p = mount_p->next;
			kfree(rsbac_mount_list);
		}
		rsbac_mount_list = NULL;
	}

/* Tell that rsbac is initialized                                       */
	rsbac_initialized = TRUE;

/* Force a check, if configured */
#ifdef CONFIG_RSBAC_INIT_CHECK
	rsbac_pr_debug(stack, "free stack before rsbac_check: %lu\n",
		       rsbac_stack_free_space());
	rsbac_printk(KERN_INFO "rsbac_do_init(): Forcing consistency check.\n");
	rsbac_check_lists(1);
#if defined(CONFIG_RSBAC_ACL)
	rsbac_check_acl(1);
#endif
#endif

	if (!current->fs) {
		rsbac_printk(KERN_WARNING "rsbac_do_init(): current->fs is invalid!\n");
		err = -RSBAC_EINVALIDPOINTER;
	} else {
		err = 0;
	}

out:
	/* We are up and running */
	rsbac_printk(KERN_INFO "rsbac_do_init(): Ready.\n");

	kfree(list_info_p);
	return err;
}


#ifdef CONFIG_RSBAC_INIT_THREAD
/* rsbac kernel daemon for init */
#ifdef CONFIG_RSBAC_INIT_DELAY
static int rsbac_initd(void *dummy)
#else
static int __init rsbac_initd(void *dummy)
#endif
{
	rsbac_printk(KERN_INFO "rsbac_initd(): Initializing.\n");

/* Dead loop for timeout testing */
/*    while(1) { } */

	rsbac_pr_debug(stack, "free stack before rsbac_do_init(): %lu\n",
		       rsbac_stack_free_space());
	/* init RSBAC */
	rsbac_do_init();

	rsbac_pr_debug(stack, "free stack after rsbac_do_init(): %lu\n",
		       rsbac_stack_free_space());
	/* wake up init process */
	wake_up(&rsbacd_wait);
	/* ready */
	rsbac_printk(KERN_INFO "rsbac_initd(): Exiting.\n");
	do_exit(0);
	return 0;
}
#endif

/***************************************************/
/* rsbac_write() to write all dirty lists to disk  */
/*               returns no. of lists written      */

#if defined(CONFIG_RSBAC_AUTO_WRITE)
int rsbac_trigger_write(rsbac_boolean_t force_rehash)
{
	if (force_rehash) {
		rsbac_pr_debug(write, "trigger list rehash and wake_up rsbacd\n");
		rsbac_rehash_lists(force_rehash);
	} else {
		rsbac_pr_debug(write, "wake_up rsbacd\n");
	}
	rsbacd_awake = TRUE;
	wake_up(&rsbacd_wait);
	return 0;
}

static int rsbac_write(rsbac_boolean_t force_rehash)
{
	int err = 0;
	u_int count = 0;
	int subcount;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_write(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}

	spin_lock(&rsbac_write_lock);
	while (write_blocked) {
		spin_unlock(&rsbac_write_lock);
		rsbac_pr_debug(write, "rsbac_write(): write_blocked, wait 100ms and retry\n");
		msleep_interruptible(100);
		spin_lock(&rsbac_write_lock);
	}
	write_blocked = TRUE;
	spin_unlock(&rsbac_write_lock);

	rsbac_rehash_lists(force_rehash);

	if (rsbac_debug_no_write) {
		write_blocked = FALSE;
		return 0;
	}

	subcount = rsbac_write_lists();
	if (subcount > 0) {
		count += subcount;
	} else if (subcount < 0) {
		err = subcount;
		if (err != -RSBAC_ENOTWRITABLE) {
			rsbac_printk(KERN_WARNING "rsbac_write(): rsbac_write_lists() returned error %i\n",
				     err);
		}
	}

#if defined(CONFIG_RSBAC_REG)
	subcount = rsbac_write_reg();
	if (subcount > 0) {
		count += subcount;
	} else if (subcount < 0) {
		err = subcount;
		if (err != -RSBAC_ENOTWRITABLE) {
			rsbac_printk(KERN_WARNING "rsbac_write(): rsbac_write_reg() returned error %i\n",
				     err);
		}
	}
#endif

	if (count > 0)
		rsbac_pr_debug(write, "total of %u lists written\n", count);
	write_blocked = FALSE;
	return count;
}
#endif


#if defined(CONFIG_RSBAC_AUTO_WRITE)
/* rsbac kernel daemon for auto-write */
static int rsbacd(void *dummy)
{
	struct task_struct *tsk = current;
	char *name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
	int sleep_result;
#ifdef CONFIG_RSBAC_LIST_CHECK_INTERVAL
	unsigned long list_check_time = jiffies + HZ * rsbac_list_check_interval;
#endif

	rsbac_printk(KERN_INFO "rsbacd(): Initializing.\n");

	close_fd(0);
	close_fd(1);
	close_fd(2);

	rsbac_pr_debug(auto, "rsbacd(): wake up every %us\n", auto_interval / HZ);
	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());
	ignore_signals(tsk);
	if (auto_interval > 0) {
		wait_event_interruptible_timeout(rsbacd_wait, 0, auto_interval);
	}
	for (;;) {
		if (auto_interval > 0) {
			sleep_result = wait_event_interruptible_timeout(rsbacd_wait, rsbacd_awake, auto_interval);
		} else {
			sleep_result = wait_event_interruptible(rsbacd_wait, rsbacd_awake);
		}
		if (sleep_result > 0) {
			rsbac_pr_debug(write, "woken up by rsbac_trigger_write()\n");
		}
		rsbacd_awake = FALSE;
#ifdef CONFIG_PM
		if (try_to_freeze())
		    continue;
#endif

#ifdef CONFIG_RSBAC_LIST_CHECK_INTERVAL
		/* Cleanup lists regularly */
		if (time_after_eq(jiffies, list_check_time)) {
			list_check_time = jiffies + HZ * rsbac_list_check_interval;
			rsbac_pr_debug(auto, "cleaning up lists\n");
			rsbac_check_lists(1);
		}
#endif
		/* Trigger rehashing and writing of lists */
		if (rsbac_initialized) {
			int err = 0;
			/* rsbac_pr_debug(auto, "calling rsbac_write()\n"); */
			err = rsbac_write(FALSE);
			if (err < 0) {
				if (name)
					rsbac_printk(KERN_WARNING "rsbacd(): rsbac_write returned error %s!\n",
						     get_error_name(name,
								    err));
				else
					rsbac_printk(KERN_WARNING "rsbacd(): rsbac_write returned error %i!\n",
						     err);
			} else if (err > 0)
				rsbac_pr_debug(auto, "rsbac_write() wrote %i "
					       "lists\n", err);
		}
		walk_delayed_kfree();
	}
	return 0;
}
#endif

/************************************************* */
/*               Init function                     */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac_error.h.                 */

struct rsbac_kthread_t {
	struct list_head list;
	rsbac_pid_t pid;
};
struct rsbac_kthread_t * rsbac_kthread;
DEFINE_SPINLOCK(rsbac_kthread_lock);

int rsbac_kthreads_init(void)
{
	rsbac_kthread = kmalloc(sizeof(struct rsbac_kthread_t), GFP_ATOMIC);
	INIT_LIST_HEAD(&rsbac_kthread->list);
	return 0;
}

int rsbac_mark_kthread(rsbac_pid_t pid)
{
	struct rsbac_kthread_t * rsbac_kthread_new;

	if (rsbac_initialized)
		return 0;
	rsbac_kthread_new = kmalloc(sizeof(struct rsbac_kthread_t), GFP_ATOMIC);
	rsbac_kthread_new->pid = pid;
	spin_lock(&rsbac_kthread_lock);
	list_add(&rsbac_kthread_new->list, &rsbac_kthread->list);
	spin_unlock(&rsbac_kthread_lock);
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init(rsbac_dev_t root_dev)
#else
int __init rsbac_init(rsbac_dev_t root_dev)
#endif
{
#ifdef CONFIG_RSBAC_RC
	struct rsbac_rc_process_aci_t rc_init_p_aci = DEFAULT_RC_P_INIT_ACI;
#endif
#ifdef CONFIG_RSBAC_INIT_THREAD
	struct task_struct * rsbac_init_thread;
#endif
	struct task_struct * rsbacd_thread;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC)
	rsbac_pid_t init_pid;
	struct rsbac_kthread_t * rsbac_kthread_entry;
	struct list_head * p;
#endif


	if (rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_init(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}
	if (!current->fs) {
		rsbac_printk(KERN_WARNING "rsbac_init(): current->fs is invalid!\n");
		return -RSBAC_EINVALIDPOINTER;
	}

	rsbac_root_dev = root_dev;
	rsbac_root_dev_major = RSBAC_MAJOR(root_dev);
	rsbac_root_dev_minor = RSBAC_MINOR(root_dev);

#if defined(CONFIG_RSBAC_AUTO_WRITE) || defined(CONFIG_RSBAC_INIT_THREAD)
	/* init the rsbacd wait queue head */
	init_waitqueue_head(&rsbacd_wait);
#endif

#ifdef CONFIG_RSBAC_INIT_THREAD
/* trigger dependency */
#ifdef CONFIG_RSBAC_MAX_INIT_TIME
#endif
	rsbac_printk(KERN_INFO "rsbac_init(): Setting init timeout to %u seconds (%u jiffies).\n",
		     RSBAC_MAX_INIT_TIME, RSBAC_MAX_INIT_TIME * HZ);

/* Start rsbac thread for init */
	rsbac_init_thread = kthread_create(rsbac_initd, NULL, "rsbac_initd");
	if (IS_ERR(rsbac_init_thread))
		goto panic;
	rsbacd_pid = task_pid(rsbac_init_thread);
	wake_up_process(rsbac_init_thread);
	rsbac_printk(KERN_INFO "rsbac_init(): Started rsbac_initd thread with pid %u\n",
		     pid_nr(rsbacd_pid));

	if (!wait_event_interruptible_timeout(rsbacd_wait, rsbac_initialized, RSBAC_MAX_INIT_TIME * HZ)) {
		struct kernel_siginfo info;

		rsbac_printk(KERN_ERR
			     "rsbac_init(): *** RSBAC init timed out - RSBAC not correctly initialized! ***\n");
		rsbac_printk(KERN_ERR
			     "rsbac_init(): *** Killing rsbac_initd! ***\n");
		info.si_signo = SIGKILL;
		info.si_errno = 0;
		info.si_code = SI_KERNEL;
		info.si_pid = 0;
		info.si_uid = 0;
		kill_pid_info(SIGKILL, &info, rsbacd_pid);

		rsbac_initialized = FALSE;
	}
	rsbacd_pid = NULL;
#else
	rsbac_do_init();
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE)
	if (rsbac_initialized) {
		/* Start rsbacd thread for auto write */
		rsbacd_thread = kthread_create(rsbacd, NULL, "rsbacd");
		if (IS_ERR(rsbacd_thread)) {
			rsbac_printk(KERN_ERR
				     "rsbac_init(): *** Starting rsbacd thread failed with error %i! ***\n",
				     PTR_ERR(rsbacd_thread));
		} else {
			rsbacd_pid = task_pid(rsbacd_thread);
			wake_up_process(rsbacd_thread);
			rsbac_printk(KERN_INFO "rsbac_init(): Started rsbacd thread with pid %u\n",
				     pid_nr(rsbacd_pid));
		}
	}
#endif

/* Ready. */
#ifdef CONFIG_RSBAC_INIT_THREAD
	kernel_wait4(-1, NULL, WNOHANG, NULL);
#endif

/* Add all processes to list of processes as init processes */
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC)
	{
#ifdef CONFIG_RSBAC_MAC
		struct rsbac_mac_user_aci_t * mac_u_aci_p;
#endif
#ifdef CONFIG_RSBAC_RC
		struct rsbac_rc_user_aci_t * rc_u_aci_p;
#endif
		rsbac_uid_t user = RSBAC_SYSADM_UID;
		rsbac_pid_t pid = find_pid_ns(1, &init_pid_ns);
		struct task_struct *p;

#ifdef CONFIG_RSBAC_RC
		union rsbac_target_id_t k_tid;
		union rsbac_attribute_value_t k_attr_val;
#endif

		rsbac_printk(KERN_INFO "rsbac_init(): Adjusting attributes of existing processes\n");
/* Prepare entries: change standard values to root's values */
#ifdef CONFIG_RSBAC_MAC
		mac_u_aci_p = rsbac_kmalloc_unlocked(sizeof(*mac_u_aci_p));
		if (mac_u_aci_p) {
			if(!rsbac_list_get_data
				(user_handles.mac, &user, mac_u_aci_p)) {
				mac_init_p_aci.owner_sec_level =
				    mac_u_aci_p->security_level;
				mac_init_p_aci.owner_initial_sec_level =
				    mac_u_aci_p->initial_security_level;
				mac_init_p_aci.current_sec_level =
				    mac_u_aci_p->initial_security_level;
				mac_init_p_aci.owner_min_sec_level =
				    mac_u_aci_p->min_security_level;
				mac_init_p_aci.mac_owner_categories =
				    mac_u_aci_p->mac_categories;
				mac_init_p_aci.mac_owner_initial_categories =
				    mac_u_aci_p->mac_initial_categories;
				mac_init_p_aci.mac_curr_categories =
				    mac_u_aci_p->mac_initial_categories;
				mac_init_p_aci.mac_owner_min_categories =
				    mac_u_aci_p->mac_min_categories;
				mac_init_p_aci.min_write_open =
				    mac_u_aci_p->security_level;
				mac_init_p_aci.max_read_open =
				    mac_u_aci_p->min_security_level;
				mac_init_p_aci.min_write_categories =
				    mac_u_aci_p->mac_categories;
				mac_init_p_aci.max_read_categories =
				    mac_u_aci_p->mac_min_categories;
				mac_init_p_aci.mac_process_flags =
				    (mac_u_aci_p->
				     mac_user_flags & RSBAC_MAC_P_FLAGS) |
				    RSBAC_MAC_DEF_INIT_P_FLAGS;
			}
			rsbac_kfree(mac_u_aci_p);
		}
#endif

/* Set process aci - first init */
#ifdef CONFIG_RSBAC_MAC
		if (rsbac_list_add
		    (process_handles.mac, &pid,
		     &mac_init_p_aci))
			rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for Init process 1 could not be added!");
#endif
#ifdef CONFIG_RSBAC_RC
		/* Get boot role */
		if (rsbac_rc_get_boot_role(&rc_init_p_aci.rc_role)) {	/* none: use root's role */
			rc_u_aci_p = rsbac_kmalloc_unlocked(sizeof(*rc_u_aci_p));
			if (rc_u_aci_p) {
				if (!rsbac_list_get_data
				    (user_handles.rc, &user, rc_u_aci_p)) {
					rc_init_p_aci.rc_role = rc_u_aci_p->rc_role;
				} else {	/* last resort: general role */
					rsbac_ds_get_error("rsbac_do_init",
							   A_rc_def_role);
					rc_init_p_aci.rc_role =
					    RSBAC_RC_GENERAL_ROLE;
				}
				rsbac_kfree(rc_u_aci_p);
			}
		}
		rc_kernel_p_aci.rc_role = rc_init_p_aci.rc_role;
		if (rsbac_list_add
		    (process_handles.rc, &pid,
		     &rc_init_p_aci))
			rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Init process 1 could not be added!");
#endif
		read_lock(&tasklist_lock);
		for_each_process(p)
		{
			/* not for kernel and init though... */
			if ((!p->pid) || (p->pid == 1))
				continue;
			pid = task_pid(p);
			rsbac_pr_debug(ds, "setting aci for process %u (%s)\n", pid, p->comm);
#ifdef CONFIG_RSBAC_MAC
			if (rsbac_list_add
			    (process_handles.mac, &pid,
			     &mac_init_p_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for Init process %u could not be added!\n",
					     pid);
#endif
#ifdef CONFIG_RSBAC_RC
			k_tid.process = pid;
			if (rsbac_get_attr(SW_GEN, T_PROCESS,
					k_tid,
					A_kernel_thread,
					&k_attr_val,
					FALSE)) {
				rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Kernel thread %u could not be added!\n", pid);
			}
			if (k_attr_val.kernel_thread) {
				if (rsbac_list_add
				    (process_handles.rc,
				     &pid, &rc_kernel_p_aci))
					rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Kernel thread %u could not be added!\n",
					     pid);
		}
#endif
		}
		read_unlock(&tasklist_lock);
	}
	list_for_each(p, &rsbac_kthread->list) {
		rsbac_kthread_entry = list_entry(p, 
				struct rsbac_kthread_t, list);
		if (pid_nr(rsbac_kthread_entry->pid) != 1 
				&& rsbac_kthread_entry->pid != rsbacd_pid)
		{
			read_lock(&tasklist_lock);
			if(pid_task(rsbac_kthread_entry->pid, PIDTYPE_PID)) {
				read_unlock(&tasklist_lock);
				rsbac_pr_debug(ds, "Setting other ACI for kthread %u\n", pid_nr(rsbac_kthread_entry->pid));
				rsbac_kthread_notify(rsbac_kthread_entry->pid);
			}
			else {
				read_unlock(&tasklist_lock);
				rsbac_pr_debug(ds, "rsbac_do_init(): skipping gone away pid %u\n",
					pid_nr(rsbac_kthread_entry->pid));
			}
			/* kernel list implementation is for exclusive 
			 * wizards use, let's not free it now till 
			 * i know why it oops. consume about no 
			 * memory anyway. michal.
			 */
			
			/* list_del(&rsbac_kthread_entry->list);
			 * kfree(rsbac_kthread_entry);*/
		}
	} /* explicitly mark init and rsbacd */
	init_pid = find_pid_ns(1, &init_pid_ns);
#ifdef CONFIG_RSBAC_MAC
	if (rsbac_list_add(process_handles.mac, &init_pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for \"init\" process could not be added!");
	if (rsbac_list_add(process_handles.mac, &rsbacd_pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for \"rsbacd\" process could not be added!");
#endif
#ifdef CONFIG_RSBAC_RC
	if (rsbac_list_add(process_handles.rc, &init_pid, &rc_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for \"init\" process could not be added");
	if (rsbac_list_add(process_handles.rc, &rsbacd_pid, &rc_kernel_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for \"rsbacd\" process could not be added");
#endif
	
	/*kfree(rsbac_kthread);*/
#endif	/* MAC or RC */

	rsbac_printk(KERN_INFO "rsbac_init(): Ready.\n");
	return 0;

#ifdef CONFIG_RSBAC_INIT_THREAD
panic:
	rsbac_printk(KERN_ERR "rsbac_init(): *** RSBAC init failed to start - RSBAC not correctly initialized! ***\n");
	/* let's panic - but only when in secure mode, warn otherwise */
#ifdef CONFIG_RSBAC_SOFTMODE
	if (!rsbac_softmode)
#endif
		panic("RSBAC: rsbac_init(): *** Unable to initialize - PANIC ***\n");
	return -RSBAC_EINVALIDVALUE;
#endif
}

int rsbac_kthread_notify(rsbac_pid_t pid)
{
	if (!rsbac_initialized)
		return 0;
//	rsbac_printk(KERN_DEBUG "rsbac_kthread_notify: marking pid %u!\n",
//		     pid);
/* Set process aci */
#ifdef CONFIG_RSBAC_MAC
	if (rsbac_list_add
	    (process_handles.mac, &pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_kthread_notify(): MAC ACI for kernel process %u could not be added!",
			     pid_nr(pid));
#endif
#ifdef CONFIG_RSBAC_RC
	if (rsbac_list_add
	    (process_handles.rc, &pid, &rc_kernel_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_kthread_notify(): RC ACI for kernel process %u could not be added!",
			     pid_nr(pid));
#endif
	return 0;
}

/* When mounting a device, its ACI must be read and added to the ACI lists. */

EXPORT_SYMBOL(rsbac_mount);
int rsbac_mount(struct vfsmount * vfsmount_p, struct vfsmount * vfsmount_parent_p)
{
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;
	__u32 major;
	__u32 minor;
	int err = 0;

	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mount(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	if (RSBAC_IS_INVALID_PTR(vfsmount_p) || RSBAC_IS_INVALID_PTR(vfsmount_p->mnt_sb)) {
		rsbac_printk(KERN_WARNING "rsbac_mount(): called with NULL or ERR pointer\n");
		return -RSBAC_EINVALIDPOINTER;
	}
	if (!rsbac_allow_mounts) {
		struct rsbac_mount_list_t * mount_p;

#ifdef CONFIG_RSBAC_INIT_DELAY
		if (!RSBAC_MAJOR(rsbac_delayed_root)
		    && !RSBAC_MINOR(rsbac_delayed_root)
		    && rsbac_delayed_root_str[0]
		    ) {		/* translate string to rsbac_dev_t */
			char *p = rsbac_delayed_root_str;
			u_int major = 0;
			u_int minor = 0;

			major = simple_strtoul(p, NULL, 0);
			while ((*p != ':') && (*p != '\0'))
				p++;
			if (*p) {
				p++;
				minor = simple_strtoul(p, NULL, 0);
			}
			rsbac_delayed_root = RSBAC_MKDEV(major, minor);
		}
		if (   !rsbac_no_delay_init
		    && ((!RSBAC_MAJOR(rsbac_delayed_root)
			 && !RSBAC_MINOR(rsbac_delayed_root)
			 && (MAJOR(vfsmount_p->mnt_sb->s_dev) > 1)
			)
			|| ((RSBAC_MAJOR(rsbac_delayed_root)
			     || RSBAC_MINOR(rsbac_delayed_root)
			    )
			    &&
			    ((MAJOR(vfsmount_p->mnt_sb->s_dev) ==
			      RSBAC_MAJOR(rsbac_delayed_root))
			     && (!RSBAC_MINOR(rsbac_delayed_root)
				 || (MINOR(vfsmount_p->mnt_sb->s_dev) ==
				     RSBAC_MINOR(rsbac_delayed_root))
			     )
			    )
			)
		    )
		    ) {
			if (RSBAC_MAJOR(rsbac_delayed_root)
			    || RSBAC_MINOR(rsbac_delayed_root)) {
				rsbac_printk(KERN_INFO "rsbac_mount(): forcing delayed RSBAC init on DEV %02u:%02u, matching %02u:%02u!\n",
					     MAJOR(vfsmount_p->mnt_sb->s_dev),
					     MINOR(vfsmount_p->mnt_sb->s_dev),
					     RSBAC_MAJOR
					     (rsbac_delayed_root),
					     RSBAC_MINOR
					     (rsbac_delayed_root));
			} else {
				rsbac_printk(KERN_INFO "rsbac_mount(): forcing delayed RSBAC init on DEV %02u:%02u!\n",
					     MAJOR(vfsmount_p->mnt_sb->s_dev),
					     MINOR(vfsmount_p->mnt_sb->s_dev));
			}
			rsbac_root_vfsmount_p = vfsmount_p;
			rsbac_init(vfsmount_p->mnt_sb->s_dev);
			return 0;
		}
#endif

		rsbac_printk(KERN_WARNING "rsbac_mount(): RSBAC not initialized while mounting DEV %02u:%02u, fs-type %s, delaying\n",
				MAJOR(vfsmount_p->mnt_sb->s_dev), MINOR(vfsmount_p->mnt_sb->s_dev),
				vfsmount_p->mnt_sb->s_type->name);
		mount_p = kmalloc(sizeof(*mount_p), GFP_KERNEL);
		if (mount_p) {
			mount_p->vfsmount_p = mntget(vfsmount_p);
			if (!RSBAC_IS_INVALID_PTR(vfsmount_parent_p))
				mount_p->vfsmount_parent_p = mntget(vfsmount_parent_p);
			else
				mount_p->vfsmount_parent_p = NULL;
			mount_p->next = rsbac_mount_list;
			rsbac_mount_list = mount_p;
		}

		return -RSBAC_ENOTINITIALIZED;
	}

	/* serialize mounts */
	spin_lock(&rsbac_mount_lock);
	while (rsbac_mount_pid != NULL) {
		spin_unlock(&rsbac_mount_lock);
		msleep_interruptible(100);
		spin_lock(&rsbac_mount_lock);
	}
	rsbac_mount_pid = task_pid(current);
	spin_unlock(&rsbac_mount_lock);

	major = RSBAC_MAJOR(vfsmount_p->mnt_sb->s_dev);
	minor = RSBAC_MINOR(vfsmount_p->mnt_sb->s_dev);
	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());
	if (!RSBAC_IS_INVALID_PTR(vfsmount_parent_p)) {
		__u32 pmajor;
		__u32 pminor;

		pmajor = RSBAC_MAJOR(vfsmount_parent_p->mnt_sb->s_dev);
		pminor = RSBAC_MINOR(vfsmount_parent_p->mnt_sb->s_dev);
		rsbac_pr_debug(ds, "mounting device %02u:%02u, parent %02u:%02u\n",
				major, minor, pmajor, pminor);
		hash = device_hash(pminor);
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(pmajor, pminor, hash);
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		if(device_p) {
			rsbac_pr_debug(ds, "found parent %02u:%02u\n",
					pmajor, pminor);
		} else {
			rsbac_printk(KERN_WARNING "rsbac_mount(): while mounting device %02u:%02u, fs-type %s, its parent device %02u:%02u, fs-type %s, is not mounted, forcing parent mount!\n",
				major, minor,
				vfsmount_p->mnt_sb->s_type->name,
				pmajor, pminor,
				vfsmount_parent_p->mnt_sb->s_type->name);
			rsbac_mount(vfsmount_parent_p, NULL);
		}
	} else {
		rsbac_pr_debug(ds, "mounting device %02u:%02u, no parent given\n",
				major, minor);
	}
	hash = device_hash(minor);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	/* repeated mount? */
	if (device_p) {
		rsbac_printk(KERN_INFO "rsbac_mount: repeated mount %u of device %02u:%02u, fs_type %s (%lx)\n",
			     device_p->mount_count, major, minor,
			    vfsmount_p->mnt_sb->s_type->name,
			    vfsmount_p->mnt_sb->s_magic);
		device_p->mount_count++;
		if (!device_p->vfsmount_p)
			device_p->vfsmount_p = mntget(vfsmount_p);
		else
			if (   real_mount(device_p->vfsmount_p)->mnt_mountpoint
			    && (real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb->s_dev == device_p->vfsmount_p->mnt_sb->s_dev)
		    	   ) {
#if defined(CONFIG_RSBAC_AUTO_WRITE)
				spin_lock(&rsbac_write_lock);
				while (write_blocked) {
					spin_unlock(&rsbac_write_lock);
					rsbac_pr_debug(write, "rsbac_mount(): write_blocked, wait 100ms and retry\n");
					msleep_interruptible(100);
					spin_lock(&rsbac_write_lock);
				}
				write_blocked = TRUE;
				spin_unlock(&rsbac_write_lock);
#endif
				mntput(device_p->vfsmount_p);
				device_p->vfsmount_p = mntget(vfsmount_p);
#if defined(CONFIG_RSBAC_AUTO_WRITE)
				write_blocked = FALSE;
#endif
			}
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	} else {
		struct rsbac_device_list_item_t *new_device_p;

		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		/* OK, go on */
		new_device_p = create_device_item(vfsmount_p, major, minor);
		rsbac_pr_debug(stack, "after creating device item: free stack: %lu\n",
			       rsbac_stack_free_space());
		if (!new_device_p) {
			rsbac_mount_pid = NULL;
			return -RSBAC_ECOULDNOTADDDEVICE;
		}

		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		/* make sure to only add, if this device item has not been added in the meantime */
		device_p = lookup_device(major, minor, hash);
		if (device_p) {
			rsbac_printk(KERN_WARNING "rsbac_mount(): mount race for device %02u:%02u detected!\n",
				     major, minor);
			device_p->mount_count++;
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			clear_device_item(new_device_p);
		} else {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			device_p = add_device_item(new_device_p, TRUE);
			if (!device_p) {
				rsbac_mount_pid = NULL;
				rsbac_printk(KERN_WARNING "rsbac_mount: adding device %02u:%02u failed!\n",
					     major, minor);
				clear_device_item(new_device_p);
				return -RSBAC_ECOULDNOTADDDEVICE;
			}

			mntget(device_p->vfsmount_p);
		}

		/* we do not lock device head - we know the device_p and hope for the best... */
		/* also, we are within kernel mount sem */
		if ((err = register_fd_lists(new_device_p, major, minor))) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "rsbac_mount(): File/Dir ACI registration failed for dev %02u:%02u, err %s!\n",
					     major, minor,
					     get_error_name(tmp, err));
				rsbac_kfree(tmp);
			}
		}
		rsbac_pr_debug(stack, "after registering fd lists: free stack: %lu\n",
			       rsbac_stack_free_space());
#ifdef CONFIG_RSBAC_FD_CACHE
		if (rsbac_want_cache(new_device_p))
			register_fd_cache_lists(new_device_p);
#endif

	}

/* call other mount functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_mount_mac(major, minor);
	rsbac_pr_debug(stack, "after mount_mac: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_mount_auth(major, minor);
	rsbac_pr_debug(stack, "after mount_auth: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_mount_acl(major, minor);
	rsbac_pr_debug(stack, "after mount_acl: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_REG)
	rsbac_mount_reg(major, minor);
	rsbac_pr_debug(stack, "after mount_reg: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif				/* REG */

	rsbac_mount_pid = NULL;

	return err;
}

/* When umounting a device, its ACI must be removed from the ACI lists.     */
/* Removing the device ACI should be no problem.                            */

EXPORT_SYMBOL(rsbac_umount);
int rsbac_umount(struct vfsmount *vfsmount_p)
{
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;

	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	if (!vfsmount_p) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): called with NULL pointer\n");
		return -RSBAC_EINVALIDPOINTER;
	}
	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): RSBAC not initialized\n");
		if (rsbac_mount_list) {
			struct rsbac_mount_list_t * mount_p;
			struct rsbac_mount_list_t * prev_mount_p;

			mount_p = rsbac_mount_list;
			prev_mount_p = NULL;
			while (mount_p) {
				if (mount_p->vfsmount_p == vfsmount_p) {
					mntput(vfsmount_p);
					if(mount_p->vfsmount_parent_p)
						mntput(mount_p->vfsmount_parent_p);
					rsbac_printk(KERN_WARNING "rsbac_umount(): found delayed mount for device %02u:%02u, removing\n",
							RSBAC_MAJOR(vfsmount_p->mnt_sb->s_dev), RSBAC_MINOR(vfsmount_p->mnt_sb->s_dev));
					if (prev_mount_p) {
						prev_mount_p->next = mount_p->next;
						kfree (mount_p);
						mount_p = prev_mount_p->next;
					} else {
						rsbac_mount_list = mount_p->next;
						kfree (mount_p);
						mount_p = rsbac_mount_list;
					}
					break;
				} else {
					prev_mount_p = mount_p;
					mount_p = mount_p->next;
				}
			}
		}

		return -RSBAC_ENOTINITIALIZED;
	}
	major = RSBAC_MAJOR(vfsmount_p->mnt_sb->s_dev);
	minor = RSBAC_MINOR(vfsmount_p->mnt_sb->s_dev);
	rsbac_pr_debug(ds, "umounting device %02u:%02u\n",
		       major, minor);

	/* sync attribute lists */
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	/* serialize mounts */
	spin_lock(&rsbac_mount_lock);
	while (rsbac_mount_pid != NULL) {
		spin_unlock(&rsbac_mount_lock);
		msleep_interruptible(100);
		spin_lock(&rsbac_mount_lock);
	}
	rsbac_mount_pid = task_pid(current);
	spin_unlock(&rsbac_mount_lock);
	rsbac_write(FALSE);
	rsbac_mount_pid = NULL;
#endif
/* call other umount functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_umount_mac(major, minor);
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_umount_auth(major, minor);
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_umount_acl(major, minor);
#endif
#if defined(CONFIG_RSBAC_REG)
	rsbac_umount_reg(major, minor);
#endif

	hash = device_hash(minor);
	/* wait for write access to device_list_head */
	spin_lock(&device_list_locks[hash]);
	while (!RSBAC_IS_AUTO_DEV(umount_device_in_progress_major, umount_device_in_progress_minor)) {
		DECLARE_WAIT_QUEUE_HEAD(auto_wait);

		spin_unlock(&device_list_locks[hash]);
		wait_event_interruptible_timeout(auto_wait, !RSBAC_IS_AUTO_DEV(umount_device_in_progress_major, umount_device_in_progress_minor), HZ);
		spin_lock(&device_list_locks[hash]);
	}
	umount_device_in_progress_major = major;
	umount_device_in_progress_minor = minor;
	device_p = lookup_device_locked(major, minor, hash);
	if (device_p) {
		if (device_p->mount_count == 1) {
			/* remove_device_item unlocks device_list_locks[hash]! */
			remove_device_item(major, minor, hash);
#ifdef CONFIG_RSBAC_FD_CACHE
			unregister_fd_cache_lists(device_p);
#endif
			aci_detach_fd_lists(device_p);
			if (device_p->vfsmount_p)
				mntput(device_p->vfsmount_p);
			clear_device_item(device_p);
			spin_lock(&device_list_locks[hash]);
		} else {
			if (device_p->mount_count > 1) {
				device_p->mount_count--;
				if (device_p->vfsmount_p == vfsmount_p) {
					device_p->vfsmount_p = NULL;
					spin_unlock(&device_list_locks[hash]);
					mntput(vfsmount_p);
					rsbac_printk(KERN_WARNING "rsbac_umount: removed primary mount for device %02u:%02u, inheritance broken!\n",
						     major, minor);
					spin_lock(&device_list_locks[hash]);
				}
			} else {
				rsbac_printk(KERN_WARNING "rsbac_umount: device %02u:%02u has mount_count < 1!\n",
					     major, minor);
			}
		}
	}
	umount_device_in_progress_major = RSBAC_AUTO_DEV_NUM;
	umount_device_in_progress_minor = RSBAC_AUTO_DEV_NUM;
	spin_unlock(&device_list_locks[hash]);

	return 0;
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats(void)
{
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	long fd_count;
	u_long fd_sum = 0;
	u_long dev_sum = 0;
	u_long ipc_sum = 0;
	u_long user_sum = 0;
	u_long process_sum = 0;
#if defined(CONFIG_RSBAC_UM)
	u_long group_sum = 0;
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
	u_long nettemp_sum = 0;
	u_long lnetobj_sum = 0;
	u_long rnetobj_sum = 0;
#endif
	u_long total_sum = 0;
	long tmp_count = 0;
	u_int i;
	int srcu_idx;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_stats(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
		while (device_p) {	/* for all sublists */
			fd_count = rsbac_list_count(device_p->handles.gen);
			if (fd_count > 0) {
				rsbac_printk(", %lu GEN", fd_count);
				fd_sum += fd_count;
			}

#if defined(CONFIG_RSBAC_MAC)
			fd_count = rsbac_list_count(device_p->handles.mac);
			if (fd_count > 0) {
				rsbac_printk(", %lu MAC", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_FF)
			fd_count = rsbac_list_count(device_p->handles.ff);
			if (fd_count > 0) {
				rsbac_printk(", %lu FF", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RC)
			fd_count = rsbac_list_count(device_p->handles.rc);
			if (fd_count > 0) {
				rsbac_printk(", %lu RC", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_AUTH)
			fd_count = rsbac_list_count(device_p->handles.auth);
			if (fd_count > 0) {
				rsbac_printk(", %lu AUTH", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_CAP)
			fd_count = rsbac_list_count(device_p->handles.cap);
			if (fd_count > 0) {
				rsbac_printk(", %lu CAP", fd_count);
				fd_sum += fd_count;
			}
#endif
#if defined(CONFIG_RSBAC_RES)
			fd_count = rsbac_list_lol_count(device_p->handles.res_min);
			if (fd_count > 0) {
				rsbac_printk(", %lu RES MIN", fd_count);
				fd_sum += fd_count;
			}
			fd_count = rsbac_list_lol_count(device_p->handles.res_max);
			if (fd_count > 0) {
				rsbac_printk(", %lu RES MAX", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_UDF)
			fd_count = rsbac_list_count(device_p->handles.udf);
			if (fd_count > 0) {
				rsbac_printk(", %lu UDF", fd_count);
				fd_sum += fd_count;
			}
#if defined(CONFIG_RSBAC_UDF_CACHE)
			fd_count = rsbac_list_count(device_p->handles.udfc);
			if (fd_count > 0) {
				rsbac_printk(", %lu UDF CHECKED", fd_count);
				fd_sum += fd_count;
			}
#endif
#endif

			rsbac_printk("\n");
			device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
		}
		tmp_count += device_head_p[i]->count;
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	rsbac_printk(KERN_INFO "rsbac_stats(): Sum of %u Devices with %lu fd-items\n",
		     tmp_count, fd_sum);
	/* free access to device_list_head */
	total_sum += fd_sum;

	/* dev lists */
	tmp_count = rsbac_list_count(dev_handles.gen);
	rsbac_printk(KERN_INFO "DEV items: %lu GEN", tmp_count);
	dev_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(dev_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	dev_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(dev_major_handles.rc);
	rsbac_printk(", %lu major RC", tmp_count);
	dev_sum += tmp_count;
	tmp_count = rsbac_list_count(dev_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	dev_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu DEV items\n", dev_sum);
	total_sum += dev_sum;

	/* ipc lists */
	rsbac_printk(KERN_INFO "IPC items: no GEN");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(ipc_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	ipc_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(ipc_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	ipc_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(ipc_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	ipc_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu IPC items\n", ipc_sum);
	total_sum += ipc_sum;

	/* user lists */
	tmp_count = rsbac_list_count(user_handles.gen);
	rsbac_printk(KERN_INFO "USER items: %lu GEN", tmp_count);
	user_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(user_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(user_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(user_handles.auth);
	rsbac_printk(", %lu AUTH", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(user_handles.cap);
	rsbac_printk(", %lu CAP", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(user_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_list_lol_count(user_handles.res_min);
	rsbac_printk(", %lu RES MIN", tmp_count);
	user_sum += tmp_count;
	tmp_count = rsbac_list_lol_count(user_handles.res_max);
	rsbac_printk(", %lu RES MAX", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_UDF)
	tmp_count = rsbac_list_count(user_handles.udf);
	rsbac_printk(", %lu UDF", tmp_count);
	user_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu USER items\n", user_sum);
	total_sum += user_sum;

	/* process lists */
	tmp_count = rsbac_list_count(process_handles.gen);
	rsbac_printk(KERN_INFO "PROCESS items: %lu GEN", tmp_count);
	process_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(process_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(process_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(process_handles.auth);
	rsbac_printk(", %lu AUTH", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(process_handles.cap);
	rsbac_printk(", %lu CAP", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(process_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_UDF)
	tmp_count = rsbac_list_count(process_handles.udf);
	rsbac_printk(", %lu UDF", tmp_count);
	process_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu PROCESS items\n", process_sum);
	total_sum += process_sum;

#if defined(CONFIG_RSBAC_UM)
	/* group lists */
	rsbac_printk(KERN_INFO "GROUP items: ");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	tmp_count = rsbac_list_count(group_handles.rc);
	rsbac_printk("%lu RC", tmp_count);
	user_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu GROUP items\n", group_sum);
	total_sum += group_sum;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	/* nettemp lists */
	rsbac_printk(KERN_INFO "NETTEMP items: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(nettemp_handles.mac);
	rsbac_printk("%lu MAC, ", tmp_count);
	nettemp_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(nettemp_handles.rc);
	rsbac_printk("%lu RC, ", tmp_count);
	nettemp_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu NETTEMP items\n", nettemp_sum);
	total_sum += nettemp_sum;

	/* local netobj lists */
	rsbac_printk(KERN_INFO "Local NETOBJ items:");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(lnetobj_handles.mac);
	rsbac_printk(" %lu MAC,", tmp_count);
	lnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	tmp_count = rsbac_list_count(lnetobj_handles.rc);
	rsbac_printk(" %lu RC", tmp_count);
	lnetobj_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu Local NETOBJ items\n",
		     lnetobj_sum);
	total_sum += lnetobj_sum;

	/* remote netobj lists */
	rsbac_printk(KERN_INFO "Remote NETOBJ items:");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(rnetobj_handles.mac);
	rsbac_printk(" %lu MAC,", tmp_count);
	rnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	tmp_count = rsbac_list_count(rnetobj_handles.rc);
	rsbac_printk(" %lu RC", tmp_count);
	rnetobj_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu Remote NETOBJ items\n",
		     rnetobj_sum);
	total_sum += rnetobj_sum;
#endif				/* NET_OBJ */

	rsbac_printk(KERN_INFO "Total of %lu registered rsbac-items\n", total_sum);

	rsbac_printk(KERN_INFO "adf_request calls: file: %lu, dir: %lu, fifo: %lu, symlink: %lu, dev: %lu, ipc: %lu, scd: %lu, user: %lu, process: %lu, netdev: %lu, nettemp: %lu, netobj: %lu, unixsock: %lu\n",
		     rsbac_adf_request_count[T_FILE],
		     rsbac_adf_request_count[T_DIR],
		     rsbac_adf_request_count[T_FIFO],
		     rsbac_adf_request_count[T_SYMLINK],
		     rsbac_adf_request_count[T_DEV],
		     rsbac_adf_request_count[T_IPC],
		     rsbac_adf_request_count[T_SCD],
		     rsbac_adf_request_count[T_USER],
		     rsbac_adf_request_count[T_PROCESS],
		     rsbac_adf_request_count[T_NETDEV],
		     rsbac_adf_request_count[T_NETTEMP],
		     rsbac_adf_request_count[T_NETOBJ],
		     rsbac_adf_request_count[T_UNIXSOCK]);
	rsbac_printk(KERN_INFO "adf_set_attr calls: file: %lu, dir: %lu, fifo: %lu, symlink: %lu, dev: %lu, ipc: %lu, scd: %lu, user: %lu, process: %lu, netdev: %lu, nettemp: %lu, netobj: %lu, unixsock: %lu\n",
		     rsbac_adf_set_attr_count[T_FILE],
		     rsbac_adf_set_attr_count[T_DIR],
		     rsbac_adf_set_attr_count[T_FIFO],
		     rsbac_adf_set_attr_count[T_SYMLINK],
		     rsbac_adf_set_attr_count[T_DEV],
		     rsbac_adf_set_attr_count[T_IPC],
		     rsbac_adf_set_attr_count[T_SCD],
		     rsbac_adf_set_attr_count[T_USER],
		     rsbac_adf_set_attr_count[T_PROCESS],
		     rsbac_adf_set_attr_count[T_NETDEV],
		     rsbac_adf_set_attr_count[T_NETTEMP],
		     rsbac_adf_set_attr_count[T_NETOBJ],
		     rsbac_adf_set_attr_count[T_UNIXSOCK]);

#if defined(CONFIG_RSBAC_RC)
	rsbac_stats_rc();
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_stats_auth();
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_stats_acl();
#endif
	return 0;
}

/************************************************* */
/*               Attribute functions               */
/************************************************* */

/* A rsbac_set_attr() call for a non-existing object, user                  */
/* or process entry will first add the target and then set the attribute.   */
/* Invalid combinations and trying to set security_level to or from         */
/* SL_rsbac_internal return an error.                                       */
/* A rsbac_get_attr() call for a non-existing target will return the        */
/* default value stored in def_aci, which should be the first enum item.*/

/* All these procedures handle the rw-spinlocks to protect the targets during */
/* access.                                                                  */

/* get the parent of a target
 * returns -RSBAC_EINVALIDTARGET for non-fs targets
 * and -RSBAC_ENOTFOUND, if no parent available
 * In kernels >= 2.4.0, device_p->d_covers is used and the device_p item is
 * properly locked for reading, so never call with a write lock held on
 * device_p!
 */
#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_get_parent);
#endif
int rsbac_get_parent(enum rsbac_target_t target,
		     union rsbac_target_id_t tid,
		     enum rsbac_target_t *parent_target_p,
		     union rsbac_target_id_t *parent_tid_p)
{
	int srcu_idx;

	if (!parent_target_p || !parent_tid_p)
		return -RSBAC_EINVALIDPOINTER;
/*
	rsbac_pr_debug(ds, "Getting file/dir/fifo/symlink "
		       "parent for device %02u:%02u, inode %lu, dentry_p %p\n",
		       RSBAC_MAJOR(tid.file.device),
		       RSBAC_MINOR(tid.file.device),
		       (u_long)tid.file.inode, tid.file.dentry_p);
*/
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		break;
	default:
		return -RSBAC_EINVALIDTARGET;
	}

	if (RSBAC_IS_INVALID_PTR(tid.file.dentry_p))
		return -RSBAC_ENOTFOUND;

#ifdef CONFIG_RSBAC_XSTATS
	data_race(get_parent_count++);
#endif
	*parent_target_p = T_DIR;
	/* Is this dentry root of a mounted device? */
	if (   !RSBAC_IS_INVALID_PTR(tid.file.dentry_p->d_sb)
	    && (tid.file.dentry_p->d_sb->s_root == tid.file.dentry_p)
	    ) {
		struct rsbac_device_list_item_t *device_p;
		u_int hash;
		__u32 major;
		__u32 minor;

		if (tid.file.device == rsbac_root_dev)
			return -RSBAC_ENOTFOUND;
		major = RSBAC_MAJOR(tid.file.device);
		minor = RSBAC_MINOR(tid.file.device);
		hash = device_hash(minor);
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(major, minor, hash);
		if (   !device_p
		    || !device_p->vfsmount_p
		    || RSBAC_IS_INVALID_PTR(real_mount(device_p->vfsmount_p)->mnt_mountpoint)
		    || RSBAC_IS_INVALID_PTR(real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent)
		    || (real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent == real_mount(device_p->vfsmount_p)->mnt_mountpoint)
		    || RSBAC_IS_INVALID_PTR(real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent->d_sb)
		    || !real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent->d_inode
		    || !real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent->d_inode->i_ino
		    || RSBAC_IS_INVALID_PTR(real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb)
		    || !real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb->s_dev
		    || (real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_sb->s_dev == tid.file.device)) {
			/* free access to device_list_head */
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			return -RSBAC_ENOTFOUND;
		}
		parent_tid_p->dir.device =
		    real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent->d_sb->s_dev;
		parent_tid_p->dir.inode =
		    real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent->d_inode->i_ino;
		parent_tid_p->dir.dentry_p =
		    real_mount(device_p->vfsmount_p)->mnt_mountpoint->d_parent;
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	} else {		/* no root of filesystem -> use d_parent, dev keeps unchanged */
		if (RSBAC_IS_INVALID_PTR(tid.file.dentry_p->d_parent)) {
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent is NULL or ERR!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (tid.file.dentry_p == tid.file.dentry_p->d_parent) {
			// rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent == dentry_p!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (RSBAC_IS_INVALID_PTR(tid.file.dentry_p->d_parent->d_inode)) {
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent has no or invalid d_inode!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (!tid.file.dentry_p->d_parent->d_inode->i_ino)
		{
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent d_inode->i_ino is 0!\n");
			return -RSBAC_ENOTFOUND;
		}
		parent_tid_p->dir.device = tid.file.device;
		parent_tid_p->dir.inode =
		    tid.file.dentry_p->d_parent->d_inode->i_ino;
		parent_tid_p->dir.dentry_p = tid.file.dentry_p->d_parent;
	}
	return 0;
}

static int get_attr_fd(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value_p,
			rsbac_boolean_t inherit)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
#ifdef CONFIG_RSBAC_FD_CACHE
	__u32 firstdev_major = 0;
	__u32 firstdev_minor = 0;
	rsbac_inode_nr_t firstinode = 0;
#endif
#if defined(CONFIG_RSBAC_FF)
	rsbac_ff_flags_t ff_flags = 0;
	rsbac_ff_flags_t ff_tmp_flags;
	rsbac_ff_flags_t ff_mask = -1;
#endif
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;
	rsbac_old_inode_nr_t inode_nr;

	/* use loop for inheritance - used to be recursive calls */
	for (;;) {
/*		rsbac_pr_debug(ds, "Getting file/dir/fifo/"
			       "symlink attribute %u for device %02u:%02u, "
			       "inode %lu, dentry_p %p\n", attr,
			       RSBAC_MAJOR(tid_p->file.device),
			       RSBAC_MINOR(tid_p->file.device),
			       tid_p->file.inode,
			       tid_p->file.dentry_p); */
		major = RSBAC_MAJOR(tid_p->file.device);
		minor = RSBAC_MINOR(tid_p->file.device);
		hash = device_hash(minor);
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(major, minor, hash);
		if (unlikely(!device_p)) {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			if (   tid_p->file.dentry_p
			    && tid_p->file.dentry_p->d_sb
			    && tid_p->file.dentry_p->d_sb->s_type
			    && tid_p->file.dentry_p->d_sb->s_type->name
			   )
				WARN_ONCE(1, "rsbac_get_attr(): unknown device %02u:%02u (type %s), returning default value!\n",
					major, minor, tid_p->file.dentry_p->d_sb->s_type->name);
			else
				WARN_ONCE(1, "rsbac_get_attr(): unknown device %02u:%02u, returning default value!\n",
					major, minor);
		}

#ifdef CONFIG_RSBAC_FD_CACHE
		if (inherit && !ta_number && device_p->fd_cache_handle[module] && likely(device_p)) {
			rsbac_enum_t cache_attr = attr;

			if (!rsbac_list_lol_get_subdata(device_p->fd_cache_handle[module],
						&tid_p->file.inode, &cache_attr,
						value_p)) {
#ifdef CONFIG_RSBAC_DEBUG
				char * attr_name = NULL;
				char * attr_val_name = NULL;

				if (rsbac_debug_fdcache) {
					attr_name = rsbac_kmalloc(32);
					attr_val_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
				}
				if (rsbac_debug_fdcache > 1)
					rsbac_pr_debug(fdcache, "Found fd cache item device %02u:%02u inode %lu module %u attr %s value %s\n",
						major, minor,
						tid_p->file.inode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p));
#endif
#if defined(CONFIG_RSBAC_FF)
				/* FF ff_flags is special, result needs some cleaning, if inherited */
				if (attr == A_ff_flags)
					value_p->ff_flags = (value_p->ff_flags & ff_mask ) | ff_flags;
#endif
				if (!RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor) && firstinode) {
					if (firstdev_major != major || firstdev_minor != minor) {
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						hash = device_hash(firstdev_minor);
						srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
						device_p = lookup_device(firstdev_major, firstdev_minor, hash);
					}
					if (device_p && device_p->fd_cache_handle[module]) {
#ifdef CONFIG_RSBAC_DEBUG
						if (rsbac_debug_fdcache) {
							union rsbac_attribute_value_t tmp_value;

							if (!rsbac_list_lol_get_subdata(device_p->fd_cache_handle[module],
										&firstinode, &cache_attr,
										&tmp_value)) {
								rsbac_pr_debug(fdcache, "fd cache item already in cache: device %02u:%02u inode %lu module %u attr %s value %s (parent device %02u:%02u inode %lu was in cache)\n",
									firstdev_major, firstdev_minor,
									firstinode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, &tmp_value),
									RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
									tid_p->file.inode);
							}
						}
#endif
						rsbac_pr_debug(fdcache, "Adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (parent device %02u:%02u inode %lu was in cache)\n",
							firstdev_major, firstdev_minor,
							firstinode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p),
							RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
							tid_p->file.inode);
						err = rsbac_list_lol_subadd_ttl(device_p->fd_cache_handle[module],
								rsbac_fd_cache_ttl,
								&firstinode, &cache_attr,
								value_p);
#ifdef CONFIG_RSBAC_DEBUG
						if (err && rsbac_debug_fdcache) {
							rsbac_pr_debug(fdcache, "Adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (parent device %02u:%02u inode %lu was in cache) failed with error %i\n",
								firstdev_major, firstdev_minor,
								firstinode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p),
								RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
								tid_p->file.inode,
								err);
						}
#endif
#ifdef CONFIG_RSBAC_XSTATS
						data_race(device_p->fd_cache_misses[module]++);
#endif
					}
#ifdef CONFIG_RSBAC_DEBUG
					else {
						if (rsbac_debug_fdcache > 1)
							rsbac_pr_debug(fdcache, "Not adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (parent device %02u:%02u inode %lu was in cache)\n",
								firstdev_major, firstdev_minor,
								firstinode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p),
								RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
								tid_p->file.inode);
					}
#endif
#ifdef CONFIG_RSBAC_XSTATS
				} else {
					data_race(device_p->fd_cache_hits[module]++);
#endif
				}
#ifdef CONFIG_RSBAC_DEBUG
				if (attr_name)
					rsbac_kfree(attr_name);
				if (attr_val_name)
					rsbac_kfree(attr_val_name);
#endif
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				return 0;
			}
		}
#endif

		inode_nr = tid_p->file.inode;

		switch (module) {
		case SW_GEN:
			{
				struct rsbac_gen_fd_aci_t aci = DEFAULT_GEN_FD_ACI;

				if (attr == A_internal) {
					if (unlikely(!device_p)) {
						value_p->internal = FALSE;
						return 0;
					}
					if (!device_p->rsbac_dir_inode
					    || !tid_p->file.inode)
						value_p->internal = FALSE;
					else if (device_p->
						 rsbac_dir_inode ==
						 tid_p->file.inode)
						value_p->internal = TRUE;
					else if (inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (!rsbac_get_parent(target, *tid_p, &parent_target, &parent_tid)) {	/* yes: inherit this single level */
							if (device_p->rsbac_dir_inode == parent_tid.file.inode)
								value_p->internal = TRUE;
							else
								value_p->internal = FALSE;
						} else {
							value_p->internal = FALSE;
						}
					} else {
						value_p->internal = FALSE;
					}

					/* free access to device_list_head */
					srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
					return 0;
				}
				if (likely(device_p))
					rsbac_ta_list_get_data_ttl(ta_number,
								   device_p->handles.gen,
								   NULL,
								   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
								   &aci);
				switch (attr) {
				case A_log_array_low:
					value_p->log_array_low =
					    aci.log_array_low;
					break;
				case A_log_array_high:
					value_p->log_array_high =
					    aci.log_array_high;
					break;
				case A_log_program_based:
					value_p->log_program_based =
					    aci.log_program_based;
					break;
				case A_symlink_add_remote_ip:
					value_p->symlink_add_remote_ip =
					    aci.symlink_add_remote_ip;
					break;
				case A_symlink_add_uid:
					value_p->symlink_add_uid =
					    aci.symlink_add_uid;
					break;
				case A_symlink_add_mac_level:
					value_p->symlink_add_mac_level =
					    aci.symlink_add_mac_level;
					break;
				case A_symlink_add_rc_role:
					value_p->symlink_add_rc_role =
					    aci.symlink_add_rc_role;
					break;
				case A_allow_write_exec:
					value_p->allow_write_exec =
					    aci.allow_write_exec;
					if (   value_p->allow_write_exec == AWX_inherit
					    && inherit
					   ) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent (target,
									*tid_p,
									&parent_target,
									&parent_tid)) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->allow_write_exec = def_gen_root_dir_aci.allow_write_exec;
							err = 0;
							break;
						}
					}
					break;
				case A_fake_root_uid:
					value_p->fake_root_uid = aci.fake_root_uid;
					break;
				case A_auid_exempt:
					value_p->auid_exempt = aci.auid_exempt;
					break;
				case A_vset:
					value_p->vset = aci.vset;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;

#if defined(CONFIG_RSBAC_MAC)
		case SW_MAC:
			{
				struct rsbac_mac_fd_aci_t aci =
				    DEFAULT_MAC_FD_ACI;

				if (likely(device_p))
					rsbac_ta_list_get_data_ttl(ta_number,
								   device_p->handles.mac,
								   NULL,
								   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
								   &aci);
				switch (attr) {
				case A_security_level:
					value_p->security_level = aci.sec_level;
					if ((value_p->security_level == SL_inherit) && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->security_level = def_mac_root_dir_aci.sec_level;
							err = 0;
							break;
						}
					}
					break;
				case A_mac_categories:
					value_p->mac_categories =
					    aci.mac_categories;
					if ((value_p->mac_categories ==
					     RSBAC_MAC_INHERIT_CAT_VECTOR)
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p-> mac_categories = def_mac_root_dir_aci.mac_categories;
							err = 0;
							break;
						}
					}
					break;
				case A_mac_auto:
					value_p->mac_auto = aci.mac_auto;
					if ((value_p->mac_auto == MA_inherit)
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->mac_auto = def_mac_root_dir_aci.mac_auto;
							err = 0;
							break;
						}
					}
					break;
				case A_mac_prop_trusted:
					value_p->mac_prop_trusted =
					    aci.mac_prop_trusted;
					break;
				case A_mac_file_flags:
					value_p->mac_file_flags =
					    aci.mac_file_flags;
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_FF)
		case SW_FF:
			{
				switch (attr) {
				case A_ff_flags:
					ff_tmp_flags = RSBAC_FF_DEF;
					if (likely(device_p))
						rsbac_ta_list_get_data_ttl(ta_number,
									device_p->handles.ff,
									NULL,
									device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
									&ff_tmp_flags);
					ff_flags |= ff_tmp_flags & ff_mask;
					value_p->ff_flags = ff_flags;
					if (   (ff_tmp_flags & FF_add_inherited)
					    && inherit) {
						enum rsbac_target_t parent_target;
						union rsbac_target_id_t parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							ff_mask &= ~ (FF_no_delete_or_rename | FF_add_inherited);
							ff_flags &= ~(FF_add_inherited);
							continue;
						} else
							value_p->ff_flags &= ~(FF_add_inherited);
					}
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
		case SW_RC:
			{
				struct rsbac_rc_fd_aci_t aci =
				    DEFAULT_RC_FD_ACI;

				if (likely(device_p))
					rsbac_ta_list_get_data_ttl(ta_number,
								device_p->handles.rc,
								NULL,
								device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
								&aci);
				switch (attr) {
				case A_rc_type_fd:
					value_p->rc_type_fd = aci.rc_type_fd;
					if (   value_p->rc_type_fd == RC_type_inherit_parent
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->rc_type_fd = def_rc_root_dir_aci.rc_type_fd;
							err = 0;
							break;
						}
					}
					break;
				case A_rc_force_role:
					value_p->rc_force_role = aci.rc_force_role;
					if (   value_p->rc_force_role == RC_role_inherit_parent
					    && inherit
					   ) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->rc_force_role = def_rc_root_dir_aci.rc_force_role;
							err = 0;
							break;
						}
					}
					break;
				case A_rc_initial_role:
					value_p->rc_initial_role = aci.rc_initial_role;
					if (   value_p->rc_initial_role == RC_role_inherit_parent
					    && inherit
					   ) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->rc_initial_role = def_rc_root_dir_aci.rc_initial_role;
							err = 0;
							break;
						}
					}
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
		case SW_AUTH:
			{
				struct rsbac_auth_fd_aci_t aci =
				    DEFAULT_AUTH_FD_ACI;

				if (likely(device_p))
					rsbac_ta_list_get_data_ttl(ta_number,
								   device_p->handles.auth,
								   NULL,
								   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
								   &aci);
				switch (attr) {
				case A_auth_may_setuid:
					value_p->auth_may_setuid =
					    aci.auth_may_setuid;
					break;
				case A_auth_may_set_cap:
					value_p->auth_may_set_cap =
					    aci.auth_may_set_cap;
					break;
				case A_auth_learn:
					value_p->auth_learn = aci.auth_learn;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
		case SW_CAP:
			{
				struct rsbac_cap_fd_aci_t aci =
				    DEFAULT_CAP_FD_ACI;

				if (likely(device_p))
					rsbac_ta_list_get_data_ttl(ta_number,
								   device_p->handles.cap,
								   NULL,
								   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
								   &aci);
				switch (attr) {
				case A_min_caps:
					value_p->min_caps = aci.min_caps;
					break;
				case A_max_caps:
					value_p->max_caps = aci.max_caps;
					break;
				case A_cap_ld_env:
					value_p->cap_ld_env = aci.cap_ld_env;
					if ((value_p->cap_ld_env == LD_inherit) && inherit) {
						enum rsbac_target_t parent_target;
						union rsbac_target_id_t parent_tid;
						if (   likely(device_p)
						    && !rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)
						   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
							if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
								firstdev_major = device_p->major;
								firstdev_minor = device_p->minor;
								firstinode = tid_p->file.inode;
							}
#endif
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value_p->cap_ld_env = LD_deny;
							err = 0;
							break;
						}
					}
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_RES)
		case SW_RES:
			{
				long item_count;
				char * array_p;
				char * tmp;
				int size;
				int i;
				rsbac_res_desc_t res_num;

				memset(&value_p->res_array, 0, sizeof(value_p->res_array));

				switch (attr) {
					case A_res_min:
						if(unlikely(!device_p))
							break;
						item_count = rsbac_list_lol_get_all_subitems_ttl(device_p->handles.res_min, &tid_p->file.inode, (void **) &array_p, NULL);
						if (item_count > 0) {
							tmp = array_p;
							size = rsbac_list_lol_get_subitem_size(device_p->handles.res_min);

							for (i = 0; i < item_count; i++) {
								res_num = *((rsbac_res_desc_t *) tmp);
								if (res_num > RSBAC_RES_MAX)
									continue;
								value_p->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
								tmp += size;
							}
							rsbac_kfree(array_p);
						}
						break;
					case A_res_max:
						if(unlikely(!device_p))
							break;
						item_count = rsbac_list_lol_get_all_subitems_ttl(device_p->handles.res_max, &tid_p->file.inode, (void **) &array_p, NULL);
						if (item_count > 0) {
							tmp = array_p;
							size = rsbac_list_lol_get_subitem_size(device_p->handles.res_max);

							for (i = 0; i < item_count; i++) {
								res_num = *((rsbac_res_desc_t *) tmp);
								if (res_num > RSBAC_RES_MAX)
									continue;
								value_p->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
								tmp += size;
							}
							rsbac_kfree(array_p);
						}
						break;
					default:
						err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* RES */

#if defined(CONFIG_RSBAC_UDF)
		case SW_UDF:
			{
#if defined(CONFIG_RSBAC_UDF_CACHE)
				if (attr == A_udf_checked) {
					if (likely(device_p)) {
						err = rsbac_ta_list_get_data_ttl(ta_number,
							device_p->handles.udfc,
							NULL,
#ifdef CONFIG_RSBAC_UDF_PERSIST
							device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
#else
							&tid_p->file.inode,
#endif
							&value_p->udf_checked);
					} else {
						value_p->udf_checked = UDF_unchecked;
						err = 0;
					}
				} else
#endif
				{
					struct rsbac_udf_fd_aci_t aci =
					    DEFAULT_UDF_FD_ACI;

					if (likely(device_p))
						rsbac_ta_list_get_data_ttl(ta_number,
									device_p->handles.udf,
									NULL,
									device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
									&aci);
					switch (attr) {
					case A_udf_checker:
						value_p->udf_checker =
						    aci.udf_checker;
						break;
					case A_udf_do_check:
						value_p->udf_do_check = aci.udf_do_check;
						if(   value_p->udf_do_check == UDF_inherit
						   && inherit
						  ) {
							enum rsbac_target_t       parent_target;
							union rsbac_target_id_t   parent_tid;

							if (   likely(device_p)
							    && !rsbac_get_parent(target,
										*tid_p,
										&parent_target,
										&parent_tid)
							   ) {
#ifdef CONFIG_RSBAC_FD_CACHE
								if (RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
									firstdev_major = device_p->major;
									firstdev_minor = device_p->minor;
									firstinode = tid_p->file.inode;
								}
#endif
								srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
								target = parent_target;
								*tid_p = parent_tid;
								continue;
							} else {
								value_p->udf_do_check
									= def_udf_root_dir_aci.udf_do_check;
								err = 0;
								break;
							}
						}
						break;
					default:
						err = -RSBAC_EINVALIDATTR;
					}
				}
			}
			break;
#endif				/* UDF */

		default:
			err = -RSBAC_EINVALIDMODULE;
		}
#ifdef CONFIG_RSBAC_FD_CACHE
		if (!err && inherit && !ta_number && likely(device_p) ) {
			rsbac_enum_t cache_attr = attr;
#ifdef CONFIG_RSBAC_DEBUG
			char * attr_name = NULL;
			char * attr_val_name = NULL;
			if (rsbac_debug_fdcache) {
				attr_name = rsbac_kmalloc(32);
				attr_val_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			}
#endif
			if (!RSBAC_IS_ZERO_DEV(firstdev_major, firstdev_minor)) {
				if (firstdev_major != major || firstdev_minor != minor) {
					srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
					hash = device_hash(firstdev_minor);
					srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
					device_p = lookup_device(firstdev_major, firstdev_minor, hash);
					tid_p->file.device = RSBAC_MKDEV(firstdev_major, firstdev_minor);
				}
			}
			if (device_p && device_p->fd_cache_handle[module]) {
				if (firstinode)
					tid_p->file.inode = firstinode;
				rsbac_pr_debug(fdcache, "Adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (no parent was in cache)\n",
					RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
					tid_p->file.inode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p));
				err = rsbac_list_lol_subadd_ttl(device_p->fd_cache_handle[module],
						rsbac_fd_cache_ttl,
						&tid_p->file.inode, &cache_attr,
						value_p);
				if (err) {
#ifdef CONFIG_RSBAC_DEBUG
					if (rsbac_debug_fdcache) {
						rsbac_pr_debug(fdcache, "Adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (parent device %02u:%02u inode %lu was in cache) failed with error %i\n",
								firstdev_major, firstdev_minor,
								firstinode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p),
								RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
								tid_p->file.inode,
								err);
					}
#endif
					err = 0;
				}
#ifdef CONFIG_RSBAC_XSTATS
				data_race(device_p->fd_cache_misses[module]++);
#endif
			}
#ifdef CONFIG_RSBAC_DEBUG
			else {
				if (rsbac_debug_fdcache > 1)
					rsbac_pr_debug(fdcache, "Not adding fd cache item device %02u:%02u inode %lu module %u attr %s value %s (no parent was in cache)\n",
						RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
						tid_p->file.inode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p));
			}
			if (attr_name)
				rsbac_kfree(attr_name);
			if (attr_val_name)
				rsbac_kfree(attr_val_name);
#endif
		}
#endif /* CONFIG_RSBAC_FD_CACHE */

		/* free access to device_list_head */
		if (likely(device_p))
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		/* and return */
		return err;
	}			/* end of for(;;) loop for inheritance */
}

static int get_attr_dev(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			struct rsbac_dev_desc_t dev,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
/*	rsbac_pr_debug(ds, "Getting dev attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_dev_aci_t aci =
			    DEFAULT_GEN_DEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.gen,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_dev_aci_t aci =
			    DEFAULT_MAC_DEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.mac,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;
			case A_mac_check:
				value->mac_check = aci.mac_check;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			switch (dev.type) {
			case D_char:
			case D_block:
				if (rsbac_ta_list_get_data_ttl(ta_number,
							       dev_handles.
							       rc, NULL,
							       &dev, &type)
				    || ((type == RC_type_inherit_parent)
					&& inherit)
				    ) {
				    	dev.minor = 0;
					rsbac_ta_list_get_data_ttl
					    (ta_number,
					     dev_major_handles.rc, NULL,
					     &dev, &type);
				}
				break;
			case D_char_major:
			case D_block_major:
				dev.type -= (D_block_major - D_block);
			    	dev.minor = 0;
				rsbac_ta_list_get_data_ttl(ta_number,
							   dev_major_handles.
							   rc, NULL, &dev,
							   &type);
				break;
			default:
				return -RSBAC_EINVALIDTARGET;
			}
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_ipc(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting ipc attribute\n"); */
	/* lookup only, if not sock or (sock-id != NULL), OK with NULL fifo */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_ipc_aci_t aci =
			    DEFAULT_MAC_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.mac,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.rc,
						   NULL,
						   &tid_p->ipc, &type);
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_jail_id_t id = RSBAC_JAIL_DEF_ID;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.jail,
						   NULL, &tid_p->ipc, &id);
			switch (attr) {
			case A_jail_id:
				value->jail_id = id;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_user(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
#if defined(CONFIG_RSBAC_UM_VIRTUAL) || defined(CONFIG_RSBAC_RES)
	rsbac_uid_t all_user;
#endif

	/* rsbac_pr_debug(ds, "Getting user attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_user_aci_t aci =
			    DEFAULT_GEN_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.gen,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_pseudo:
				value->pseudo = aci.pseudo;
				break;
			case A_log_user_based:
				value->log_user_based = aci.log_user_based;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_user_aci_t aci =
			    DEFAULT_MAC_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.mac,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_security_level:
				value->security_level = aci.security_level;
				break;
			case A_initial_security_level:
				value->security_level =
				    aci.initial_security_level;
				break;
			case A_min_security_level:
				value->security_level =
				    aci.min_security_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;
			case A_mac_initial_categories:
				value->mac_categories =
				    aci.mac_initial_categories;
				break;
			case A_mac_min_categories:
				value->mac_categories =
				    aci.mac_min_categories;
				break;
			case A_system_role:
			case A_mac_role:
				value->system_role = aci.system_role;
				break;
			case A_mac_user_flags:
				value->mac_user_flags = aci.mac_user_flags;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.ff,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.ff,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.ff,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_ff_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_user_aci_t aci = DEFAULT_RC_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.rc,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_rc_def_role:
				value->rc_def_role = aci.rc_role;
				break;
			case A_rc_type:
				value->rc_type = aci.rc_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.auth,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.auth,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.auth,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_auth_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_user_aci_t aci =
			    DEFAULT_CAP_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.cap,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_system_role:
			case A_cap_role:
				value->system_role = aci.cap_role;
				break;
			case A_min_caps:
				value->min_caps = aci.min_caps;
				break;
			case A_max_caps:
				value->max_caps = aci.max_caps;
				break;
			case A_cap_ld_env:
				value->cap_ld_env = aci.cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.jail,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.jail,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.jail,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_jail_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		if (attr == A_system_role || attr == A_res_role) {
			rsbac_system_role_int_t res_role;

			err = rsbac_ta_list_lol_get_data_ttl(ta_number,
						   user_handles.res_max,
						   NULL,
						   &tid_p->user, &res_role);
			value->system_role = res_role;
		} else {
			long item_count;
			char * array_p;
			char * tmp;
			int size;
			int i;
			rsbac_res_desc_t res_num;

			all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
			memset(&value->res_array, 0, sizeof(value->res_array));

			switch (attr) {
				case A_res_min:
					if(inherit) {
						item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_min, &all_user, (void **) &array_p, NULL);
						if (item_count > 0) {
							tmp = array_p;
							size = rsbac_list_lol_get_subitem_size(user_handles.res_min);

							for (i = 0; i < item_count; i++) {
								res_num = *((rsbac_res_desc_t *) tmp);
								if (res_num > RSBAC_RES_MAX)
									continue;
								value->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
								tmp += size;
							}
							rsbac_kfree(array_p);
						}
					}
					item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_min, &tid_p->user, (void **) &array_p, NULL);
					if (item_count > 0) {
						tmp = array_p;
						size = rsbac_list_lol_get_subitem_size(user_handles.res_min);

						for (i = 0; i < item_count; i++) {
							res_num = *((rsbac_res_desc_t *) tmp);
							if (res_num > RSBAC_RES_MAX)
								continue;
							value->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
							tmp += size;
						}
						rsbac_kfree(array_p);
					}
					break;
				case A_res_max:
					if(inherit) {
						item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_max, &all_user, (void **) &array_p, NULL);
						if (item_count > 0) {
							tmp = array_p;
							size = rsbac_list_lol_get_subitem_size(user_handles.res_max);

							for (i = 0; i < item_count; i++) {
								res_num = *((rsbac_res_desc_t *) tmp);
								if (res_num > RSBAC_RES_MAX)
									continue;
								value->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
								tmp += size;
							}
							rsbac_kfree(array_p);
						}
					}
					item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_max, &tid_p->user, (void **) &array_p, NULL);
					if (item_count > 0) {
						tmp = array_p;
						size = rsbac_list_lol_get_subitem_size(user_handles.res_max);
						for (i = 0; i < item_count; i++) {
							res_num = *((rsbac_res_desc_t *) tmp);
							if (res_num > RSBAC_RES_MAX)
								continue;
							value->res_array[res_num] = *( (rsbac_res_limit_t*) (tmp + sizeof(rsbac_res_desc_t)) );
							tmp += size;
						}
						rsbac_kfree(array_p);
					}
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RES */

#if defined(CONFIG_RSBAC_UDF)
	case SW_UDF:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.udf,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.udf,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.udf,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_udf_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* UDF */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_process(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value,
			    rsbac_boolean_t inherit)
{
	int err = 0;
/*	rsbac_pr_debug(ds, "Getting process attribute"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_process_aci_t aci =
			    DEFAULT_GEN_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.gen,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_vset:
				value->vset = aci.vset;
				break;
#ifdef CONFIG_RSBAC_MPROTECT
			case A_allow_write_exec:
				value->allow_write_exec = aci.allow_write_exec;
				break;
#endif
			case A_log_program_based:
				value->log_program_based =
				    aci.log_program_based;
				break;
			case A_fake_root_uid:
				value->fake_root_uid = aci.fake_root_uid;
				break;
			case A_audit_uid:
				value->audit_uid = aci.audit_uid;
				break;
			case A_auid_exempt:
				value->auid_exempt = aci.auid_exempt;
				break;
			case A_remote_ip:
				value->remote_ip = aci.remote_ip;
				break;
			case A_kernel_thread:
				value->kernel_thread = aci.kernel_thread;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_process_aci_t aci =
			    DEFAULT_MAC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.mac,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_security_level:
				value->security_level =
				    aci.owner_sec_level;
				break;
			case A_initial_security_level:
				value->security_level =
				    aci.owner_initial_sec_level;
				break;
			case A_min_security_level:
				value->security_level =
				    aci.owner_min_sec_level;
				break;
			case A_mac_categories:
				value->mac_categories =
				    aci.mac_owner_categories;
				break;
			case A_mac_initial_categories:
				value->mac_categories =
				    aci.mac_owner_initial_categories;
				break;
			case A_mac_min_categories:
				value->mac_categories =
				    aci.mac_owner_min_categories;
				break;
			case A_current_sec_level:
				value->current_sec_level =
				    aci.current_sec_level;
				break;
			case A_mac_curr_categories:
				value->mac_categories =
				    aci.mac_curr_categories;
				break;
			case A_min_write_open:
				value->min_write_open = aci.min_write_open;
				break;
			case A_min_write_categories:
				value->mac_categories =
				    aci.min_write_categories;
				break;
			case A_max_read_open:
				value->max_read_open = aci.max_read_open;
				break;
			case A_max_read_categories:
				value->mac_categories =
				    aci.max_read_categories;
				break;
			case A_mac_process_flags:
				value->mac_process_flags =
				    aci.mac_process_flags;
				break;
			case A_mac_auto:
				if (aci.mac_process_flags & MAC_auto)
					value->mac_auto = TRUE;
				else
					value->mac_auto = FALSE;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_process_aci_t aci =
			    DEFAULT_RC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.rc,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_rc_role:
				value->rc_role = aci.rc_role;
				break;
			case A_rc_type:
				value->rc_type = aci.rc_type;
				break;
			case A_rc_select_type:
				value->rc_select_type = aci.rc_select_type;
				break;
			case A_rc_force_role:
				value->rc_force_role = aci.rc_force_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_process_aci_t aci =
			    DEFAULT_AUTH_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.auth,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_auth_may_setuid:
				value->auth_may_setuid =
				    aci.auth_may_setuid;
				break;
			case A_auth_may_set_cap:
				value->auth_may_set_cap =
				    aci.auth_may_set_cap;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
			case A_auth_start_uid:
				value->auth_start_uid = aci.auth_start_uid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
			case A_auth_start_euid:
				value->auth_start_euid =
				    aci.auth_start_euid;
				break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
			case A_auth_start_gid:
				value->auth_start_gid = aci.auth_start_gid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
			case A_auth_start_egid:
				value->auth_start_egid =
				    aci.auth_start_egid;
				break;
#endif
#endif
			case A_auth_learn:
				value->auth_learn = aci.auth_learn;
				break;
#else
			case A_auth_learn:
				value->auth_learn = FALSE;
				break;
#endif
			case A_auth_last_auth:
				value->auth_last_auth = aci.auth_last_auth;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_process_aci_t aci =
			    DEFAULT_CAP_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.cap,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_max_caps_user:
				value->max_caps_user = aci.max_caps_user;
				break;
			case A_max_caps_program:
				value->max_caps_program = aci.max_caps_program;
				break;
#endif
			case A_cap_ld_env:
				value->cap_ld_env = aci.cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			struct rsbac_jail_process_aci_t aci =
			    DEFAULT_JAIL_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.jail,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_jail_id:
				value->jail_id = aci.id;
				break;
			case A_jail_parent:
				value->jail_parent = aci.parent;
				break;
			case A_jail_ip:
				value->jail_ip = aci.ip;
				break;
			case A_jail_flags:
				value->jail_flags = aci.flags;
				break;
			case A_jail_max_caps:
				value->jail_max_caps = aci.max_caps;
				value->jail_max_caps = aci.max_caps;
				break;
			case A_jail_scd_get:
				value->jail_scd_get = aci.scd_get;
				break;
			case A_jail_scd_modify:
				value->jail_scd_modify = aci.scd_modify;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

#if defined(CONFIG_RSBAC_UDF)
	case SW_UDF:
		{
			struct rsbac_udf_process_aci_t aci =
			    DEFAULT_UDF_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.udf,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_udf_checker:
				value->udf_checker = aci.udf_checker;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* UDF */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}

#ifdef CONFIG_RSBAC_UM
static int get_attr_group(rsbac_list_ta_number_t ta_number,
			  enum rsbac_switch_target_t module,
			  enum rsbac_target_t target,
			  union rsbac_target_id_t *tid_p,
			  enum rsbac_attribute_t attr,
			  union rsbac_attribute_value_t *value,
			  rsbac_boolean_t inherit)
{
	int err = 0;

	/* rsbac_pr_debug(ds, "Getting group attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   group_handles.rc,
						   NULL,
						   &tid_p->group, &type);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					rsbac_gid_t all_group;

					all_group = RSBAC_GEN_GID(RSBAC_GID_SET(tid_p->group), RSBAC_ALL_GROUPS);
					rsbac_ta_list_get_data_ttl(ta_number,
								group_handles.rc,
								NULL,
								&all_group,
								&type);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   group_handles.rc,
						   NULL,
						   &tid_p->group, &type);
#endif
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_DEV
static int get_attr_netdev(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value,
			   rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting netdev attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netdev_aci_t aci =
			    DEFAULT_GEN_NETDEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.gen,
						   NULL,
						   &tid_p->netdev, &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.rc,
						   NULL,
						   &tid_p->netdev, &type);
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
static int get_attr_nettemp(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value,
			    rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting nettemp attribute"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_fd_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;

			if (tid_p->nettemp)
				rsbac_ta_list_get_data_ttl(ta_number,
							   nettemp_handles.gen,
							   NULL,
							   &tid_p->nettemp,
							   &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.mac,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_nettemp_aci_t aci =
			    DEFAULT_RC_NETTEMP_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.rc,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_rc_type:
				value->rc_type = aci.netobj_type;
				break;

			case A_rc_type_nt:
				value->rc_type = aci.nettemp_type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}

static int get_attr_netobj(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value,
			   rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting netobj attribute"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netobj_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;
			rsbac_net_temp_id_t temp;

			switch (attr) {
			case A_local_log_array_low:
			case A_local_log_array_high:
				if(!ta_number && tid_p->netobj.local_temp)
					temp = tid_p->netobj.local_temp;
				else
					rsbac_ta_net_lookup_templates(ta_number,
								      &tid_p->
								      netobj,
								      &temp, NULL);
				break;
			case A_remote_log_array_low:
			case A_remote_log_array_high:
				if(!ta_number && tid_p->netobj.remote_temp)
					temp = tid_p->netobj.remote_temp;
				else
					rsbac_ta_net_lookup_templates(ta_number,
								      &tid_p->
								      netobj, NULL,
								      &temp);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (temp)
				rsbac_ta_list_get_data_ttl(ta_number,
							   nettemp_handles.
							   gen, NULL,
							   &temp, &aci);
			switch (attr) {
			case A_local_log_array_low:
			case A_remote_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_local_log_array_high:
			case A_remote_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			switch (attr) {
			case A_local_sec_level:
			case A_local_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.local_temp)
						temp = tid_p->netobj.local_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_sec_level:
			case A_remote_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.remote_temp)
						temp = tid_p->netobj.remote_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			switch (attr) {
			case A_local_sec_level:
			case A_remote_sec_level:
				value->security_level = aci.sec_level;
				break;
			case A_local_mac_categories:
			case A_remote_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			switch (attr) {
			case A_local_rc_type:
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.rc, NULL, &tid_p->netobj.sock_p, &type))	/* not found -> fallback to template */
#endif
				{
					rsbac_net_temp_id_t temp = 0;
					struct rsbac_rc_nettemp_aci_t aci;

					if(!ta_number && tid_p->netobj.local_temp)
						temp = tid_p->netobj.local_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     &temp, NULL);
					if (temp) {
						if (!rsbac_ta_list_get_data_ttl(ta_number, nettemp_handles.rc, NULL, &temp, &aci))
							type = aci.netobj_type;
					}
				}
				break;

			case A_remote_rc_type:
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.rc, NULL, &tid_p->netobj.sock_p, &type))	/* not found -> fallback to template */
#endif
				{
					rsbac_net_temp_id_t temp = 0;
					struct rsbac_rc_nettemp_aci_t aci;

					if(!ta_number && tid_p->netobj.remote_temp)
						temp = tid_p->netobj.remote_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     NULL, &temp);
					if (temp) {
						if (!rsbac_ta_list_get_data_ttl(ta_number, nettemp_handles.rc, NULL, &temp, &aci))
							type =
							    aci.
							    netobj_type;
					}
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err)
				value->rc_type = type;
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_FD_CACHE
int rsbac_fd_cache_invalidate(struct rsbac_fs_file_t * file_p)
{
	int i;
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;

	if (!file_p)
		return -RSBAC_EINVALIDPOINTER;
	major = RSBAC_MAJOR(file_p->device);
	if (major <= 1)
		return 0;
	minor = RSBAC_MINOR(file_p->device);

	rsbac_pr_debug(fdcache, "Invalidating fd cache item device %02u:%02u inode %lu\n",
			RSBAC_MAJOR(file_p->device), RSBAC_MINOR(file_p->device),
			file_p->inode);

	hash = device_hash(minor);

	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_fd_cache_invalidate(): No entry for device %02u:%02u\n",
			     major, minor);
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}

	for (i = 0; i < SW_NONE; i++) {
		if (device_p->fd_cache_handle[i])
			rsbac_list_lol_remove(device_p->fd_cache_handle[i], &file_p->inode);
	}
#ifdef CONFIG_RSBAC_XSTATS
	data_race(device_p->fd_cache_invalidates++);
#endif
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	return 0;
}

int rsbac_fd_cache_invalidate_device(__u32 major, __u32 minor)
{
	int i;
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;

	if (major <= 1)
		return 0;
	rsbac_pr_debug(fdcache, "Invalidating fd cache for device %02u:%02u\n",
			major, minor);

	hash = device_hash(minor);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_fd_cache_invalidate(): No entry for device %02u:%02u\n",
			     major, minor);
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}

	for (i = 0; i < SW_NONE; i++) {
		if (device_p->fd_cache_handle[i])
			rsbac_list_lol_remove_all(device_p->fd_cache_handle[i]);
	}
#ifdef CONFIG_RSBAC_XSTATS
	data_race(device_p->fd_cache_invalidate_alls++);
#endif
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	return 0;
}

int rsbac_fd_cache_invalidate_all(void)
{
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	u_int i, j;
	int srcu_idx;

	rsbac_pr_debug(fdcache, "Invalidating fd cache completely\n");

	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
		while (device_p) {	/* for all sublists */
			for (j = 0; j < SW_NONE; j++) {
				if (device_p->fd_cache_handle[j])
					rsbac_list_lol_remove_all(device_p->fd_cache_handle[j]);
			}
#ifdef CONFIG_RSBAC_XSTATS
			data_race(device_p->fd_cache_invalidate_alls++);
#endif
			device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	return 0;
}
#endif

/* The value parameter to rsbac_get_attr(s) and rsbac_set_attr() is a pointer */
/* to the appropiate data structure holding the attribute value.            */

int rsbac_ta_get_attr(rsbac_list_ta_number_t ta_number,
		      enum rsbac_switch_target_t module,
		      enum rsbac_target_t target,
		      union rsbac_target_id_t tid,
		      enum rsbac_attribute_t attr,
		      union rsbac_attribute_value_t *value_p,
		      rsbac_boolean_t inherit)
{
	int err = 0;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_get_attr(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (!value_p)
		return -RSBAC_EINVALIDPOINTER;
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_get_attr(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
#ifdef CONFIG_RSBAC_XSTATS
	data_race(get_attr_count[target]++);
#endif
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		return get_attr_fd(ta_number, module, target, &tid,
				   attr, value_p, inherit);

	case T_DEV:
		return get_attr_dev(ta_number, module, target, tid.dev,
				    attr, value_p, inherit);

	case T_IPC:
		return get_attr_ipc(ta_number, module, target, &tid,
				    attr, value_p, inherit);

	case T_USER:
		return get_attr_user(ta_number, module, target, &tid,
				     attr, value_p, inherit);

	case T_PROCESS:
		return get_attr_process(ta_number, module, target, &tid,
					attr, value_p, inherit);

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		return get_attr_group(ta_number, module, target, &tid,
				      attr, value_p, inherit);
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
		return get_attr_netdev(ta_number, module, target, &tid,
				       attr, value_p, inherit);
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
		return get_attr_nettemp(ta_number, module, target, &tid,
					attr, value_p, inherit);

	case T_NETOBJ:
		return get_attr_netobj(ta_number, module, target, &tid,
				       attr, value_p, inherit);
#endif

		/* switch target: no valid target */
	default:
		return -RSBAC_EINVALIDTARGET;
	}

	return err;
}

#ifdef CONFIG_RSBAC_RES
int rsbac_ta_get_res_limit(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid_p,
  enum rsbac_attribute_t attr,
  rsbac_res_desc_t res_num,
  rsbac_res_limit_t * value_p,
  rsbac_time_t * ttl_p,
  rsbac_boolean_t inherit)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;
	rsbac_uid_t all_user;

	if (res_num >= RLIM_NLIMITS)
		return -RSBAC_EINVALIDVALUE;

	switch (target) {
		case T_FILE:
		case T_FD:
/*			rsbac_pr_debug(ds, "Getting file/dir/fifo/"
			       "symlink attribute %u for device %02u:%02u, "
			       "inode %lu, dentry_p %p\n", attr,
			       RSBAC_MAJOR(tid_p->file.device),
			       RSBAC_MINOR(tid_p->file.device),
			       tid_p->file.inode,
			       tid_p->file.dentry_p); */
			major = RSBAC_MAJOR(tid_p->file.device);
			minor = RSBAC_MINOR(tid_p->file.device);
			hash = device_hash(minor);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(major, minor, hash);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_ta_get_res_limit(): unknown device %02u:%02u\n",
					     major, minor);
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				return -RSBAC_EINVALIDDEV;
			}
			switch (attr) {
				case A_res_min:
					err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, device_p->handles.res_min, ttl_p, &tid_p->file.inode, &res_num, value_p);
					break;
				case A_res_max:
					err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, device_p->handles.res_max, ttl_p, &tid_p->file.inode, &res_num, value_p);
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			break;

		case T_USER:
			all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
			switch (attr) {
				case A_res_min:
					err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, user_handles.res_min, ttl_p, &tid_p->user, &res_num, value_p);
					if (err && inherit)
						err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, user_handles.res_min, ttl_p, &all_user, &res_num, value_p);
					break;
				case A_res_max:
					err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, user_handles.res_max, ttl_p, &tid_p->user, &res_num, value_p);
					if (err && inherit)
						err = rsbac_ta_list_lol_get_subdata_ttl(ta_number, user_handles.res_max, ttl_p, &all_user, &res_num, value_p);
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
			break;

		/* switch target: no valid target */
		default:
			return -RSBAC_EINVALIDTARGET;
	}

	if (inherit && err == -RSBAC_ENOTFOUND) {
		*value_p = 0;
		*ttl_p = 0;
		err = 0;
	}
	return err;
}

int rsbac_ta_set_res_limit(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid_p,
  enum rsbac_attribute_t attr,
  rsbac_res_desc_t res_num,
  rsbac_res_limit_t * value_p,
  rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;

	if (res_num >= RLIM_NLIMITS)
		return -RSBAC_EINVALIDVALUE;

	if(RLIM_INFINITY > 0 && value_p && *value_p > RLIM_INFINITY)
		*value_p = RLIM_INFINITY;

	switch (target) {
		case T_FILE:
		case T_FD:
/*			rsbac_pr_debug(ds, "Getting file/dir/fifo/"
			       "symlink attribute %u for device %02u:%02u, "
			       "inode %lu, dentry_p %p\n", attr,
			       RSBAC_MAJOR(tid_p->file.device),
			       RSBAC_MINOR(tid_p->file.device),
			       tid_p->file.inode,
			       tid_p->file.dentry_p); */
			major = RSBAC_MAJOR(tid_p->file.device);
			minor = RSBAC_MINOR(tid_p->file.device);
			hash = device_hash(minor);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(major, minor, hash);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_ta_set_res_limit(): unknown device %02u:%02u\n",
					     major, minor);
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				return -RSBAC_EINVALIDDEV;
			}
			switch (attr) {
				case A_res_min:
					if (value_p)
						err = rsbac_ta_list_lol_subadd_ttl(ta_number, device_p->handles.res_min, ttl, &tid_p->file.inode, &res_num, value_p);
					else
						err = rsbac_ta_list_lol_subremove(ta_number, device_p->handles.res_min, &tid_p->file.inode, &res_num);
					break;
				case A_res_max:
					if (value_p)
						err = rsbac_ta_list_lol_subadd_ttl(ta_number, device_p->handles.res_max, ttl, &tid_p->file.inode, &res_num, value_p);
					else
						err = rsbac_ta_list_lol_subremove(ta_number, device_p->handles.res_max, &tid_p->file.inode, &res_num);
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			break;

		case T_USER:
			switch (attr) {
				case A_res_min:
					if (value_p)
						err = rsbac_ta_list_lol_subadd_ttl(ta_number, user_handles.res_min, ttl, &tid_p->user, &res_num, value_p);
					else
						err = rsbac_ta_list_lol_subremove(ta_number, user_handles.res_min, &tid_p->user, &res_num);
					break;
				case A_res_max:
					if (value_p)
						err = rsbac_ta_list_lol_subadd_ttl(ta_number, user_handles.res_max, ttl, &tid_p->user, &res_num, value_p);
					else
						err = rsbac_ta_list_lol_subremove(ta_number, user_handles.res_max, &tid_p->user, &res_num);
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
			break;

		/* switch target: no valid target */
		default:
			err = -RSBAC_EINVALIDTARGET;
	}
	return err;
}

int rsbac_get_all_res_limits(
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid_p,
  enum rsbac_attribute_t attr,
  rsbac_res_limit_t ** value_pp,
  rsbac_boolean_t inherit)
{
	struct rsbac_device_list_item_t *device_p;
	rsbac_uid_t all_user;
	__u32 major;
	__u32 minor;
	u_int hash = 0;
	int srcu_idx = 0;
	long item_count;
	long all_count = 0;
	char * array_p;
	char * all_array_p;
	char * tmp;
	int size;
	int i;
	rsbac_res_desc_t res_num;

	if (!tid_p || !value_pp)
		return -RSBAC_EINVALIDPOINTER;

	switch (target) {
		case T_FILE:
		case T_FD:
/*			rsbac_pr_debug(ds, "Getting file/dir/fifo/"
			       "symlink attribute %u for device %02u:%02u, "
			       "inode %lu, dentry_p %p\n", attr,
			       RSBAC_MAJOR(tid_p->file.device),
			       RSBAC_MINOR(tid_p->file.device),
			       tid_p->file.inode,
			       tid_p->file.dentry_p); */
			major = RSBAC_MAJOR(tid_p->file.device);
			minor = RSBAC_MINOR(tid_p->file.device);
			hash = device_hash(minor);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(major, minor, hash);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_get_all_res_limits(): unknown device %02u:%02u\n",
					     major, minor);
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				return -RSBAC_EINVALIDDEV;
			}
			switch (attr) {
				case A_res_min:
					size = rsbac_list_lol_get_subitem_size(device_p->handles.res_min);
					item_count = rsbac_list_lol_get_all_subitems_ttl(device_p->handles.res_min, &tid_p->file.inode, (void **) &array_p, NULL);
					break;
				case A_res_max:
					size = rsbac_list_lol_get_subitem_size(device_p->handles.res_max);
					item_count = rsbac_list_lol_get_all_subitems_ttl(device_p->handles.res_max, &tid_p->file.inode, (void **) &array_p, NULL);
					break;
				default:
					srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
					return -RSBAC_EINVALIDATTR;
			}
			break;

		case T_USER:
			all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
			switch (attr) {
				case A_res_min:
					all_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_min, &all_user, (void **) &all_array_p, NULL);
					item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_min, &tid_p->user, (void **) &array_p, NULL);
					size = rsbac_list_lol_get_subitem_size(user_handles.res_min);
					break;
				case A_res_max:
					all_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_max, &all_user, (void **) &all_array_p, NULL);
					item_count = rsbac_list_lol_get_all_subitems_ttl(user_handles.res_max, &tid_p->user, (void **) &array_p, NULL);
					size = rsbac_list_lol_get_subitem_size(user_handles.res_max);
					break;
				default:
					return -RSBAC_EINVALIDATTR;
			}
			break;

		/* switch target: no valid target */
		default:
			return -RSBAC_EINVALIDTARGET;
	}

	*value_pp = (rsbac_res_limit_t *) rsbac_kmalloc_clear_unlocked(RLIM_NLIMITS * sizeof(rsbac_res_limit_t));
	if (*value_pp == NULL) {
		return -RSBAC_ENOMEM;
	}
	if (all_count > 0) {
		tmp = all_array_p;

		for (i = 0; i < item_count; i++) {
			res_num = *((rsbac_res_desc_t *) tmp);
			if (res_num >= RLIM_NLIMITS) {
#if 0
				rsbac_printk(KERN_DEBUG "%s: got res_num %u >= RLIM_NLIMITS %u, skipping\n",
					     res_num, RLIM_NLIMITS);
#endif
				continue;
			}
			(*value_pp)[res_num] = *( (rsbac_res_limit_t *) (tmp + sizeof(rsbac_res_desc_t)) );
			tmp += size;
		}
		rsbac_kfree(all_array_p);
	}
	if (item_count > 0) {
		tmp = array_p;

		for (i = 0; i < item_count; i++) {
			res_num = *((rsbac_res_desc_t *) tmp);
			if (res_num >= RLIM_NLIMITS) {
#if 0
				rsbac_printk(KERN_DEBUG "%s: got res_num %u >= RLIM_NLIMITS %u, skipping\n",
					     res_num, RLIM_NLIMITS);
#endif
				continue;
			}
			(*value_pp)[res_num] = *( (rsbac_res_limit_t *) (tmp + sizeof(rsbac_res_desc_t)) );
			tmp += size;
		}
		rsbac_kfree(array_p);
	}

	switch (target) {
		case T_FILE:
		case T_FD:
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			break;
		default:
			break;
	}

	return 0;
}

#endif /* CONFIG_RSBAC_RES */
/************************************************************************** */

static int set_attr_fd_ttl(rsbac_list_ta_number_t ta_number,
		       enum rsbac_switch_target_t module,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t *tid_p,
		       enum rsbac_attribute_t attr,
		       union rsbac_attribute_value_t *value_p,
		       rsbac_time_t ttl)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;
	int need_set = 0;
	rsbac_old_inode_nr_t inode_nr = tid_p->file.inode;
#ifdef CONFIG_RSBAC_FD_CACHE
	int need_flush = 0;
#endif

	/* rsbac_pr_debug(ds, "Setting file/dir/fifo/symlink "
		       "attribute %u for device %02u:%02u, inode %lu, "
		       "dentry_p %p\n", attr,
		       RSBAC_MAJOR(tid_p->file.device),
		       RSBAC_MINOR(tid_p->file.device),
		       (u_long)tid_p->file.inode, tid_p->file.dentry_p); */
	major = RSBAC_MAJOR(tid_p->file.device);
	minor = RSBAC_MINOR(tid_p->file.device);
	hash = device_hash(minor);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(major, minor, hash);
	if (unlikely(!device_p)) {
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		if (   tid_p->file.dentry_p
		    && tid_p->file.dentry_p->d_sb
		    && tid_p->file.dentry_p->d_sb->s_type
		    && tid_p->file.dentry_p->d_sb->s_type->name)
			WARN_ONCE(1, "rsbac_set_attr_fd(): unknown device %02u:%02u (type %s), cannot set attribute!\n",
				major, minor, tid_p->file.dentry_p->d_sb->s_type->name);
		else
			WARN_ONCE(1, "rsbac_set_attr_fd(): unknown device %02u:%02u, cannot set attribute!\n",
				major, minor);
		/* Normally, we would return -RSBAC_EINVALIDDEV here.
		 * To avoid cascades of further error messages, we just return 0
		 * to let the calling function assume the value has been set.
		 */
		return 0;
	}
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_fd_aci_t aci = DEFAULT_GEN_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   device_p->handles.gen,
						   NULL,
						   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						   &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			case A_log_program_based:
				aci.log_program_based =
				    value_p->log_program_based;
				break;
			case A_symlink_add_remote_ip:
				aci.symlink_add_remote_ip =
				    value_p->symlink_add_remote_ip;
				break;
			case A_symlink_add_uid:
				aci.symlink_add_uid =
				    value_p->symlink_add_uid;
				break;
			case A_symlink_add_mac_level:
				aci.symlink_add_mac_level =
				    value_p->symlink_add_mac_level;
				break;
			case A_symlink_add_rc_role:
				aci.symlink_add_rc_role =
				    value_p->symlink_add_rc_role;
				break;
			case A_allow_write_exec:
				if (aci.allow_write_exec != value_p->allow_write_exec) {
#ifdef CONFIG_RSBAC_FD_CACHE
					if (target == T_DIR)
						need_flush = 1;
#endif
					aci.allow_write_exec = value_p->allow_write_exec;
				}
				break;
			case A_fake_root_uid:
				aci.fake_root_uid = value_p->fake_root_uid;
				break;
			case A_auid_exempt:
				aci.auid_exempt = value_p->auid_exempt;
				break;
			case A_vset:
				aci.vset = value_p->vset;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    device_p->handles.gen,
							    ttl,
							    device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							    &aci);
#ifdef CONFIG_RSBAC_FD_CACHE
				need_set = 1;
#endif
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_fd_aci_t aci = DEFAULT_MAC_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.mac,
						NULL,
						device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
#ifdef CONFIG_RSBAC_FD_CACHE
				if (target == T_DIR)
					need_flush = 1;
#endif
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
#ifdef CONFIG_RSBAC_FD_CACHE
				if (target == T_DIR)
					need_flush = 1;
#endif
				break;
			case A_mac_auto:
				aci.mac_auto = value_p->mac_auto;
#ifdef CONFIG_RSBAC_FD_CACHE
				if (target == T_DIR)
					need_flush = 1;
#endif
				break;
			case A_mac_prop_trusted:
				aci.mac_prop_trusted =
				    value_p->mac_prop_trusted;
				break;
			case A_mac_file_flags:
				aci.mac_file_flags =
				    value_p->
				    mac_file_flags & RSBAC_MAC_F_FLAGS;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->handles.mac,
							ttl,
							device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							&aci);
#ifdef CONFIG_RSBAC_FD_CACHE
				need_set = 1;
#endif
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			switch (attr) {
			case A_ff_flags:
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.ff,
							ttl,
							device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							&value_p->ff_flags);
#ifdef CONFIG_RSBAC_FD_CACHE
				if (target == T_DIR)
					need_flush = 1;
				need_set = 1;
#endif
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_fd_aci_t aci = DEFAULT_RC_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   device_p->handles.rc,
						   NULL,
						   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						   &aci);
			switch (attr) {
			case A_rc_type_fd:
				if (aci.rc_type_fd != value_p->rc_type_fd) {
#ifdef CONFIG_RSBAC_FD_CACHE
					if (target == T_DIR)
						need_flush = 1;
#endif
					aci.rc_type_fd = value_p->rc_type_fd;
					need_set = 1;
				}
				break;
			case A_rc_force_role:
				if (aci.rc_force_role != value_p->rc_force_role) {
#ifdef CONFIG_RSBAC_FD_CACHE
					if (target == T_DIR)
						need_flush = 1;
#endif
					aci.rc_force_role = value_p->rc_force_role;
					need_set = 1;
				}
				break;
			case A_rc_initial_role:
				if (aci.rc_initial_role != value_p->rc_initial_role) {
					aci.rc_initial_role = value_p->rc_initial_role;
					need_set = 1;
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (need_set) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->handles.rc,
							ttl,
							device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							&aci);
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_fd_aci_t aci =
			    DEFAULT_AUTH_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.auth,
						NULL,
						device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_auth_may_setuid:
				if (aci.auth_may_setuid != value_p->auth_may_setuid) {
					aci.auth_may_setuid = value_p->auth_may_setuid;
					need_set = 1;
				}
				break;
			case A_auth_may_set_cap:
				if (aci.auth_may_set_cap != value_p->auth_may_set_cap) {
					aci.auth_may_set_cap = value_p->auth_may_set_cap;
					need_set = 1;
				}
				break;
			case A_auth_learn:
				if (aci.auth_learn != value_p->auth_learn) {
					aci.auth_learn = value_p->auth_learn;
					need_set = 1;
				}
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (need_set) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->handles.auth,
							ttl,
							device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							&aci);
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_fd_aci_t aci = DEFAULT_CAP_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.cap,
						NULL,
						device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_min_caps:
				if (aci.min_caps != value_p->min_caps) {
					aci.min_caps = value_p->min_caps;
					need_set = 1;
				}
				break;
			case A_max_caps:
				if (aci.max_caps != value_p->max_caps) {
					aci.max_caps = value_p->max_caps;
					need_set = 1;
				}
				break;
			case A_cap_ld_env:
				if (aci.cap_ld_env != value_p->cap_ld_env) {
#ifdef CONFIG_RSBAC_FD_CACHE
					if (target == T_DIR)
						need_flush = 1;
#endif
					aci.cap_ld_env = value_p->cap_ld_env;
					need_set = 1;
				}
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (need_set) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    device_p->handles.cap,
							    ttl,
							    device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		{
			rsbac_res_desc_t res_num;
			rsbac_res_limit_t res_value;
			int tmperr;

			switch (attr) {
				case A_res_min:
					for (res_num = 0; res_num <= RSBAC_RES_MAX; res_num++) {
						res_value = value_p->res_array[res_num];
						tmperr = rsbac_ta_list_lol_subadd_ttl(ta_number,
								device_p->handles.res_min,
								0,
								&tid_p->file.inode,
								&res_num,
								&res_value);
						if (tmperr < 0) {
							err = tmperr;
							break;
						}
#ifdef CONFIG_RSBAC_FD_CACHE
						need_set = 1;
#endif
					}
					break;
				case A_res_max:
					for (res_num = 0; res_num <= RSBAC_RES_MAX; res_num++) {
						res_value = value_p->res_array[res_num];
						tmperr = rsbac_ta_list_lol_subadd_ttl(ta_number,
								device_p->handles.res_max,
								0,
								&tid_p->file.inode,
								&res_num,
								&res_value);
						if (tmperr < 0) {
							err = tmperr;
							break;
						}
#ifdef CONFIG_RSBAC_FD_CACHE
						need_set = 1;
#endif
					}
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_UDF)
	case SW_UDF:
		{
#if defined(CONFIG_RSBAC_UDF_CACHE)
			if (attr == A_udf_checked) {
				err = rsbac_list_add_ttl(device_p->handles.udfc,
						       ttl,
#ifdef CONFIG_RSBAC_UDF_PERSIST
						       device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
#else
						       &tid_p->file.inode,
#endif
						       &value_p->udf_checked);
			} else
#endif
			{
				struct rsbac_udf_fd_aci_t aci =
				    DEFAULT_UDF_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->handles.udf,
							   NULL,
							   device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
							   &aci);
				switch (attr) {
				case A_udf_checker:
					if (aci.udf_checker != value_p->udf_checker) {
						aci.udf_checker = value_p->udf_checker;
						need_set = 1;
					}
					break;
				case A_udf_do_check:
					if (aci.udf_do_check != value_p->udf_do_check) {
#ifdef CONFIG_RSBAC_FD_CACHE
						if (target == T_DIR)
							need_flush = 1;
#endif
						aci.udf_do_check = value_p->udf_do_check;
						need_set = 1;
					}
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
				if (need_set) {
					err = rsbac_ta_list_add_ttl
						(ta_number,
						device_p->handles.udf,
						ttl,
						device_p->persist ? (void *)&inode_nr : &tid_p->file.inode,
						&aci);
				}
			}
		}
		break;
#endif				/* UDF */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
#ifdef CONFIG_RSBAC_FD_CACHE
	if (!need_flush && need_set && device_p->fd_cache_handle[module]) {
#ifdef CONFIG_RSBAC_DEBUG
		char * attr_name = NULL;
		char * attr_val_name = NULL;
		if (rsbac_debug_fdcache) {
			attr_name = rsbac_kmalloc(32);
			attr_val_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		}
#endif
		rsbac_pr_debug(fdcache, "Invalidating fd cache item device %02u:%02u inode %lu, module %u, attr %s, new value %s\n",
				RSBAC_MAJOR(tid_p->file.device), RSBAC_MINOR(tid_p->file.device),
				tid_p->file.inode, module, get_attribute_name(attr_name, attr), get_attribute_value_name(attr_val_name, attr, value_p));
		rsbac_list_lol_remove(device_p->fd_cache_handle[module], &tid_p->file.inode);
#ifdef CONFIG_RSBAC_XSTATS
		data_race(device_p->fd_cache_invalidates++);
#endif
#ifdef CONFIG_RSBAC_DEBUG
		if (attr_name)
			rsbac_kfree(attr_name);
		if (attr_val_name)
			rsbac_kfree(attr_val_name);
#endif
	}
#endif

	/* free access to device_list_head */
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);

#ifdef CONFIG_RSBAC_FD_CACHE
	if (need_flush) {
		u_int i;
		struct rsbac_device_list_head_t *head_p;

		rsbac_pr_debug(fdcache, "Invalidating fd cache for module %u on all devices\n",
				module);
		for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
			srcu_idx = srcu_read_lock(&device_list_srcu[i]);
			head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
			device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
			while (device_p) {
				if (device_p->fd_cache_handle[module])
					rsbac_list_lol_remove_all(device_p->fd_cache_handle[module]);
				device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
			}
			srcu_read_unlock(&device_list_srcu[i], srcu_idx);
		}
	}
#endif

	return err;
}

static int set_attr_dev_ttl(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			struct rsbac_dev_desc_t dev,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value_p,
			rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting dev attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_dev_aci_t aci =
			    DEFAULT_GEN_DEV_ACI;

			if (dev.type > D_char)
				return -RSBAC_EINVALIDTARGET;
			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.gen,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    dev_handles.gen,
							    ttl,
							    &dev,
							    &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_dev_aci_t aci =
			    DEFAULT_MAC_DEV_ACI;

			if (dev.type > D_char)
				return -RSBAC_EINVALIDTARGET;
			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.mac,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;
			case A_mac_check:
				aci.mac_check = value_p->mac_check;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    dev_handles.mac,
							    ttl,
							    &dev,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;
			struct rsbac_dev_desc_t dev_desc;
			rsbac_list_handle_t handle;

			dev_desc.major = dev.major;
			dev_desc.minor = dev.minor;
			switch (dev.type) {
			case D_char:
				dev_desc.type = D_char;
				handle = dev_handles.rc;
				break;
			case D_block:
				dev_desc.type = D_block;
				handle = dev_handles.rc;
				break;
			case D_char_major:
				if (type > RC_type_max_value)
					return -RSBAC_EINVALIDVALUE;
				dev_desc.type = D_char;
			    	dev_desc.minor = 0;
				handle = dev_major_handles.rc;
				break;
			case D_block_major:
				if (type > RC_type_max_value)
					return -RSBAC_EINVALIDVALUE;
				dev_desc.type = D_block;
			    	dev_desc.minor = 0;
				handle = dev_major_handles.rc;
				break;
			default:
				return -RSBAC_EINVALIDTARGET;
			}

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    handle,
							    ttl,
							    &dev_desc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_ipc_ttl(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value_p,
			rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting ipc attribute"); */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_ipc_aci_t aci =
			    DEFAULT_MAC_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.mac,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.mac,
							    ttl,
							    &tid_p->ipc,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.rc,
							    ttl,
							    &tid_p->ipc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_jail_id_t id = value_p->jail_id;

			switch (attr) {
			case A_jail_id:
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.jail,
							    ttl,
							    &tid_p->ipc,
							    &id);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_user_ttl(rsbac_list_ta_number_t ta_number,
			 enum rsbac_switch_target_t module,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t *tid_p,
			 enum rsbac_attribute_t attr,
			 union rsbac_attribute_value_t *value_p,
			 rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting %s user attribute %i "
		       "for %u to %i\n",
		       get_switch_target_name(tmp, module), attr,
		       tid_p->user, value_p->dummy); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_user_aci_t aci =
			    DEFAULT_GEN_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_pseudo:
				aci.pseudo = value_p->pseudo;
				break;
			case A_log_user_based:
				aci.log_user_based =
				    value_p->log_user_based;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.gen,
							    ttl,
							    &tid_p->user,
							    &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_user_aci_t aci =
			    DEFAULT_MAC_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_security_level:
				if (value_p->security_level <
				    aci.min_security_level)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.security_level =
					    value_p->security_level;
				break;
			case A_initial_security_level:
				if ((value_p->security_level <
				     aci.min_security_level)
				    || (value_p->security_level >
					aci.security_level)
				    )
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.initial_security_level =
					    value_p->security_level;
				break;
			case A_min_security_level:
				if (value_p->security_level >
				    aci.security_level)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.min_security_level =
					    value_p->security_level;
				break;
			case A_mac_categories:
				if ((value_p->mac_categories & aci.
				     mac_min_categories) !=
				    aci.mac_min_categories)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_categories =
					    value_p->mac_categories;
				break;
			case A_mac_initial_categories:
				if (((value_p->mac_categories & aci.
				      mac_min_categories) !=
				     aci.mac_min_categories)
				    ||
				    ((value_p->mac_categories & aci.
				      mac_categories) !=
				     value_p->mac_categories)
				    )
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_initial_categories =
					    value_p->mac_categories;
				break;
			case A_mac_min_categories:
				if ((value_p->mac_categories & aci.
				     mac_categories) !=
				    value_p->mac_categories)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_min_categories =
					    value_p->mac_categories;
				break;
			case A_system_role:
			case A_mac_role:
				aci.system_role = value_p->system_role;
				break;
			case A_mac_user_flags:
				aci.mac_user_flags =
				    value_p->
				    mac_user_flags & RSBAC_MAC_U_FLAGS;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.mac,
							    ttl,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_ff_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.ff,
							    ttl,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_user_aci_t aci = DEFAULT_RC_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_rc_def_role:
				aci.rc_role = value_p->rc_def_role;
				break;
			case A_rc_type:
				aci.rc_type = value_p->rc_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.rc,
							    ttl,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_auth_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.auth,
							    ttl,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_user_aci_t aci =
			    DEFAULT_CAP_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_system_role:
			case A_cap_role:
				aci.cap_role = value_p->system_role;
				break;
			case A_min_caps:
				aci.min_caps = value_p->min_caps;
				break;
			case A_max_caps:
				aci.max_caps = value_p->max_caps;
				break;
			case A_cap_ld_env:
				aci.cap_ld_env = value_p->cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.cap,
							    ttl,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_jail_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.jail,
							    ttl,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		{
			rsbac_res_desc_t res_num;
			rsbac_res_limit_t res_value;
			rsbac_system_role_int_t res_role;
			int tmperr;

			switch (attr) {
				case A_res_min:
					for (res_num = 0; res_num <= RSBAC_RES_MAX; res_num++) {
						res_value = value_p->res_array[res_num];
						tmperr = rsbac_ta_list_lol_subadd_ttl(ta_number,
								user_handles.res_min,
								0,
								&tid_p->user,
								&res_num,
								&res_value);
						if (tmperr < 0) {
							err = tmperr;
							break;
						}
					}
					break;
				case A_res_max:
					for (res_num = 0; res_num <= RSBAC_RES_MAX; res_num++) {
						res_value = value_p->res_array[res_num];
						tmperr = rsbac_ta_list_lol_subadd_ttl(ta_number,
								user_handles.res_max,
								0,
								&tid_p->user,
								&res_num,
								&res_value);
						if (tmperr < 0) {
							err = tmperr;
							break;
						}
					}
					break;
				case A_system_role:
				case A_res_role:
					res_role = value_p->system_role;
					err = rsbac_ta_list_lol_add_ttl(ta_number,
								user_handles.res_max,
								0, &tid_p->user, &res_role);
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_UDF)
	case SW_UDF:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_udf_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.udf,
							    ttl,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_process_ttl(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value_p,
			    rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting process attribute\n"); */
	if (!tid_p->process) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): Trying to set attribute for process 0!\n");
		return -RSBAC_EINVALIDTARGET;
	}
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_process_aci_t aci =
			    DEFAULT_GEN_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.gen,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_vset:
				aci.vset = value_p->vset;
				break;
#ifdef CONFIG_RSBAC_MPROTECT
			case A_allow_write_exec:
				aci.allow_write_exec = value_p->allow_write_exec;
				break;
#endif
			case A_log_program_based:
				aci.log_program_based =
				    value_p->log_program_based;
				break;
			case A_fake_root_uid:
				aci.fake_root_uid = value_p->fake_root_uid;
				break;
			case A_audit_uid:
				aci.audit_uid = value_p->audit_uid;
				break;
			case A_auid_exempt:
				aci.auid_exempt = value_p->auid_exempt;
				break;
			case A_remote_ip:
				aci.remote_ip = value_p->remote_ip;
				break;
			case A_kernel_thread:
				aci.kernel_thread = value_p->kernel_thread;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.gen,
							    ttl,
							    &tid_p->
							    process, &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_process_aci_t aci =
			    DEFAULT_MAC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.mac,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_security_level:
				aci.owner_sec_level =
				    value_p->security_level;
				break;
			case A_initial_security_level:
				aci.owner_initial_sec_level =
				    value_p->security_level;
				break;
			case A_min_security_level:
				aci.owner_min_sec_level =
				    value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_owner_categories =
				    value_p->mac_categories;
				break;
			case A_mac_initial_categories:
				aci.mac_owner_initial_categories =
				    value_p->mac_categories;
				break;
			case A_mac_min_categories:
				aci.mac_owner_min_categories =
				    value_p->mac_categories;
				break;
			case A_current_sec_level:
				aci.current_sec_level =
				    value_p->current_sec_level;
				break;
			case A_mac_curr_categories:
				aci.mac_curr_categories =
				    value_p->mac_categories;
				break;
			case A_min_write_open:
				aci.min_write_open =
				    value_p->min_write_open;
				break;
			case A_min_write_categories:
				aci.min_write_categories =
				    value_p->mac_categories;
				break;
			case A_max_read_open:
				aci.max_read_open = value_p->max_read_open;
				break;
			case A_max_read_categories:
				aci.max_read_categories =
				    value_p->mac_categories;
				break;
			case A_mac_process_flags:
				aci.mac_process_flags =
				    value_p->
				    mac_process_flags & RSBAC_MAC_P_FLAGS;
				break;
			case A_mac_auto:
				if (value_p->mac_auto)
					aci.mac_process_flags |= MAC_auto;
				else
					aci.mac_process_flags &= ~MAC_auto;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.mac,
							    ttl,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_process_aci_t aci =
			    DEFAULT_RC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.rc,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_rc_role:
				aci.rc_role = value_p->rc_role;
				break;
			case A_rc_type:
				aci.rc_type = value_p->rc_type;
				break;
			case A_rc_select_type:
				aci.rc_select_type = value_p->rc_select_type;
				break;
			case A_rc_force_role:
				aci.rc_force_role = value_p->rc_force_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.rc,
							    ttl,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_process_aci_t aci =
			    DEFAULT_AUTH_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.auth,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_auth_may_setuid:
				aci.auth_may_setuid =
				    value_p->auth_may_setuid;
				break;
			case A_auth_may_set_cap:
				aci.auth_may_set_cap =
				    value_p->auth_may_set_cap;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
			case A_auth_start_uid:
				aci.auth_start_uid =
				    value_p->auth_start_uid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
			case A_auth_start_euid:
				aci.auth_start_euid =
				    value_p->auth_start_euid;
				break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
			case A_auth_start_gid:
				aci.auth_start_gid =
				    value_p->auth_start_gid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
			case A_auth_start_egid:
				aci.auth_start_egid =
				    value_p->auth_start_egid;
				break;
#endif
#endif
			case A_auth_learn:
				aci.auth_learn = value_p->auth_learn;
				break;
#endif
			case A_auth_last_auth:
				aci.auth_last_auth =
				    value_p->auth_last_auth;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.auth,
							    ttl,
							    &tid_p->process,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_process_aci_t aci =
			    DEFAULT_CAP_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.cap,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_max_caps_user:
				aci.max_caps_user = value_p->max_caps_user;
				break;
			case A_max_caps_program:
				aci.max_caps_program = value_p->max_caps_program;
#endif
				break;
			case A_cap_ld_env:
				aci.cap_ld_env = value_p->cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.cap,
							    ttl,
							    &tid_p->process,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			struct rsbac_jail_process_aci_t aci =
			    DEFAULT_JAIL_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.jail,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_jail_id:
				aci.id = value_p->jail_id;
				break;
			case A_jail_parent:
				aci.parent = value_p->jail_parent;
				break;
			case A_jail_ip:
				aci.ip = value_p->jail_ip;
				break;
			case A_jail_flags:
				aci.flags = value_p->jail_flags;
				break;
			case A_jail_max_caps:
				aci.max_caps = value_p->jail_max_caps;
				break;
			case A_jail_scd_get:
				aci.scd_get = value_p->jail_scd_get;
				break;
			case A_jail_scd_modify:
				aci.scd_modify = value_p->jail_scd_modify;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.jail,
							    ttl,
							    &tid_p->process,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_UDF)
	case SW_UDF:
		{
			struct rsbac_udf_process_aci_t aci =
			    DEFAULT_UDF_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.udf,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_udf_checker:
				aci.udf_checker = value_p->udf_checker;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.udf,
							    ttl,
							    &tid_p->process,
							    &aci);
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

#ifdef CONFIG_RSBAC_UM
static int set_attr_group_ttl(rsbac_list_ta_number_t ta_number,
			  enum rsbac_switch_target_t module,
			  enum rsbac_target_t target,
			  union rsbac_target_id_t *tid_p,
			  enum rsbac_attribute_t attr,
			  union rsbac_attribute_value_t *value_p,
			  rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting group attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;
			rsbac_gid_t group_desc;

			group_desc = tid_p->group;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    group_handles.rc,
							    ttl,
							    &group_desc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif				/* UM */

#ifdef CONFIG_RSBAC_NET_DEV
static int set_attr_netdev_ttl(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value_p,
			   rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting netdev attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netdev_aci_t aci =
			    DEFAULT_GEN_NETDEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.gen,
						   NULL,
						   &tid_p->netdev, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    netdev_handles.gen,
							    ttl,
							    &tid_p->netdev,
							    &aci);
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    netdev_handles.rc,
							    ttl,
							    &tid_p->netdev,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
static int set_attr_nettemp_ttl(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value_p,
			    rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting nettemp attribute\n"); */
	if (!rsbac_ta_list_exist(ta_number, net_temp_handle, &tid_p->nettemp))
		return -RSBAC_EINVALIDTARGET;
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netobj_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.gen,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.gen,
							    ttl,
							    &tid_p->nettemp,
							    &aci);
			}
		}
		break;
#endif				/* IND_NETOBJ_LOG */
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.mac,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.mac,
							    ttl,
							    &tid_p->nettemp,
							    &aci);
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_nettemp_aci_t aci =
			    DEFAULT_RC_NETTEMP_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.rc,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_rc_type:
				aci.netobj_type = value_p->rc_type;
				break;
			case A_rc_type_nt:
				aci.nettemp_type = value_p->rc_type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.rc,
							    ttl,
							    &tid_p->nettemp,
							    &aci);
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_netobj_ttl(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value_p,
			   rsbac_time_t ttl)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting netobj attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			switch (attr) {
			case A_local_sec_level:
			case A_local_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_sec_level:
			case A_remote_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			{
				switch (attr) {
				case A_local_sec_level:
					aci.sec_level = value_p->security_level;
					err = rsbac_ta_list_add_ttl(ta_number,
								lnetobj_handles.mac,
								ttl,
								&tid_p->netobj.sock_p,
								&aci);
					break;
				case A_remote_sec_level:
					aci.sec_level = value_p->security_level;
					err = rsbac_ta_list_add_ttl(ta_number,
								rnetobj_handles.mac,
								ttl,
								&tid_p->netobj.sock_p,
								&aci);
					break;
				case A_local_mac_categories:
					aci.mac_categories = value_p->mac_categories;
					err = rsbac_ta_list_add_ttl(ta_number,
								lnetobj_handles.mac,
								ttl,
								&tid_p->netobj.sock_p,
								&aci);
					break;
				case A_remote_mac_categories:
					aci.mac_categories = value_p->mac_categories;
					err = rsbac_ta_list_add_ttl(ta_number,
								rnetobj_handles.mac,
								ttl,
								&tid_p->netobj.sock_p,
								&aci);
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_local_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    lnetobj_handles.rc,
							    ttl,
							    &tid_p->netobj.
							    sock_p, &type);
				break;

			case A_remote_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    rnetobj_handles.rc,
							    ttl,
							    &tid_p->netobj.
							    sock_p, &type);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif				/* UM */


int rsbac_ta_set_attr_ttl(rsbac_list_ta_number_t ta_number,
		      enum rsbac_switch_target_t module,
		      enum rsbac_target_t target,
		      union rsbac_target_id_t tid,
		      enum rsbac_attribute_t attr,
		      union rsbac_attribute_value_t value,
		      rsbac_time_t ttl)
{
	int err = 0;
/*
#ifdef CONFIG_RSBAC_DEBUG
      char tmp[RSBAC_MAXNAMELEN];
#endif
*/
	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		err = set_attr_fd_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;

	case T_DEV:
		err = set_attr_dev_ttl(ta_number, module, target, tid.dev, attr, &value, ttl);
		break;

	case T_IPC:
		err = set_attr_ipc_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;

	case T_USER:
		err = set_attr_user_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;

	case T_PROCESS:
		err = set_attr_process_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		err = set_attr_group_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
		err = set_attr_netdev_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
		err = set_attr_nettemp_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;

	case T_NETOBJ:
		err = set_attr_netobj_ttl(ta_number, module, target, &tid, attr, &value, ttl);
		break;
#endif				/* NET_OBJ */

		/* switch(target): no valid target */
	default:
		return -RSBAC_EINVALIDTARGET;
	}
#ifdef CONFIG_RSBAC_XSTATS
	if (!err)
		data_race(set_attr_count[target]++);
#endif
	return err;
}

/************************************************************************** */

int rsbac_ta_remove_target(rsbac_list_ta_number_t ta_number,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t * tid_p)
{
	int error = 0;
	struct rsbac_device_list_item_t *device_p;
	__u32 major;
	__u32 minor;
	u_int hash;
	int srcu_idx;
	rsbac_inode_nr_t inode_nr;

	if (!rsbac_initialized) {
		// rsbac_printk(KERN_WARNING "rsbac_ta_remove_target(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_ta_remove_target(): called from interrupt!\n");
		return -RSBAC_EFROMINTERRUPT;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		inode_nr = tid_p->file.inode;
		/* rsbac_pr_debug(ds, "Removing file/dir/fifo/symlink ACI\n"); */
#if defined(CONFIG_RSBAC_MAC)
		/* file and dir items can also have mac_f_trusets -> remove first */
		if ((target == T_FILE)
		    || (target == T_DIR)
		    )
			error = rsbac_mac_remove_f_trusets(tid_p->file);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		/* file and dir items can also have auth_f_capsets -> remove first */
		if ((target == T_FILE)
		    || (target == T_DIR)
		    )
			error = rsbac_auth_remove_f_capsets(tid_p->file);
#endif
#if defined(CONFIG_RSBAC_ACL)
		/* items can also have an acl_fd_item -> remove first */
		error = rsbac_acl_remove_acl(ta_number, target, tid_p);
#endif
		major = RSBAC_MAJOR(tid_p->file.device);
		minor = RSBAC_MINOR(tid_p->file.device);
		hash = device_hash(minor);
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(major, minor, hash);
		if (unlikely(!device_p)) {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			if (   tid_p->file.dentry_p
			    && tid_p->file.dentry_p->d_sb
			    && tid_p->file.dentry_p->d_sb->s_type
			    && tid_p->file.dentry_p->d_sb->s_type->name)
				WARN_ONCE(1, "rsbac_ta_remove_target(): unknown device %02u:%02u (type %s), cannot remove attributes!\n",
					major, minor, tid_p->file.dentry_p->d_sb->s_type->name);
			else
				WARN_ONCE(1, "rsbac_ta_remove_target(): unknown device %02u:%02u, cannot remove attributes!\n",
					major, minor);
			/* Normally, we would return -RSBAC_EINVALIDDEV here.
			 * To avoid cascades of further error messages, we just return 0
			 * to let the calling function assume that all is fine.
			 */
			return 0;
		}
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.gen,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.mac,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_FF)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.ff,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.rc,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.auth,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.cap,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_RES)
		rsbac_ta_list_lol_remove(ta_number,
				     device_p->handles.res_min,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
		rsbac_ta_list_lol_remove(ta_number,
				     device_p->handles.res_max,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#endif
#if defined(CONFIG_RSBAC_UDF)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.udf,
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#if defined(CONFIG_RSBAC_UDF_CACHE)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.udfc,
#ifdef CONFIG_RSBAC_UDF_PERSIST
				     device_p->persist ? (void *)&inode_nr : &tid_p->file.inode);
#else
				     &tid_p->file.inode);
#endif
#endif
#endif

		/* free access to device_list_head */
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
#ifdef CONFIG_RSBAC_FD_CACHE
		rsbac_pr_debug(fdcache, "removed FD item device %02u:%02u inode %lu, invalidate cache item\n",
				major, minor, tid_p->file.inode);
		rsbac_fd_cache_invalidate(&tid_p->file);
#endif
		break;

	case T_DEV:
		{
			switch (tid_p->dev.type) {
				case D_block:
				case D_char:
					rsbac_ta_list_remove(ta_number,
							dev_handles.gen,
							&tid_p->dev);
#if defined(CONFIG_RSBAC_MAC)
					rsbac_ta_list_remove(ta_number,
							dev_handles.mac,
							&tid_p->dev);
#endif
#if defined(CONFIG_RSBAC_RC)
					rsbac_ta_list_remove(ta_number,
							dev_handles.rc,
							&tid_p->dev);
#endif
					break;
				case D_block_major:
				case D_char_major:
					{
						enum rsbac_dev_type_t orig_devtype=tid_p->dev.type;

						if (tid_p->dev.type==D_block_major)
							tid_p->dev.type=D_block;
						else
							tid_p->dev.type=D_char;
						rsbac_ta_list_remove(ta_number,
								dev_major_handles.gen,
								&tid_p->dev);
#if defined(CONFIG_RSBAC_MAC)
						rsbac_ta_list_remove(ta_number,
								dev_major_handles.mac,
								&tid_p->dev);
#endif
#if defined(CONFIG_RSBAC_RC)
						rsbac_ta_list_remove(ta_number,
								dev_major_handles.rc,
								&tid_p->dev);
#endif
						tid_p->dev.type=orig_devtype;
						break;
					}
				default:
					return -RSBAC_EINVALIDTARGET;
			}
		}
		break;

	case T_IPC:
		/* rsbac_pr_debug(ds, "Removing ipc ACI\n"); */
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number, ipc_handles.mac, &tid_p->ipc);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number, ipc_handles.rc, &tid_p->ipc);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     ipc_handles.jail, &tid_p->ipc);
#endif
		break;

	case T_USER:
		/* rsbac_pr_debug(ds, "Removing user ACI"); */
		rsbac_ta_list_remove(ta_number,
				     user_handles.gen, &tid_p->user);
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     user_handles.mac, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_FF)
		rsbac_ta_list_remove(ta_number,
				     user_handles.ff, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     user_handles.rc, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		rsbac_ta_list_remove(ta_number,
				     user_handles.auth, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     user_handles.cap, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     user_handles.jail, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_RES)
		rsbac_ta_list_lol_remove(ta_number,
				     user_handles.res_min, &tid_p->user);
		rsbac_ta_list_lol_remove(ta_number,
				     user_handles.res_max, &tid_p->user);
#endif
#if defined(CONFIG_RSBAC_UDF)
		rsbac_ta_list_remove(ta_number,
				     user_handles.udf, &tid_p->user);
#endif
		break;

	case T_PROCESS:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing process ACI\n");
*/
#if defined(CONFIG_RSBAC_ACL)
		/* process items can also have an acl_p_item -> remove first */
		error = rsbac_acl_remove_acl(ta_number, target, tid_p);
#endif
		rsbac_ta_list_remove(ta_number,
				     process_handles.gen,
				     &tid_p->process);
#if defined(CONFIG_RSBAC_MAC)
		/* process items can also have mac_p_trusets -> remove first */
		error = rsbac_mac_remove_p_trusets(tid_p->process);
		rsbac_ta_list_remove(ta_number,
				     process_handles.mac,
				     &tid_p->process);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     process_handles.rc,
				     &tid_p->process);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		/* process items can also have auth_p_capsets -> remove first */
		error = rsbac_auth_remove_p_capsets(tid_p->process);
		rsbac_ta_list_remove(ta_number,
				     process_handles.auth, &tid_p->process);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     process_handles.cap, &tid_p->process);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     process_handles.jail,
				     &tid_p->process);
#endif
#if defined(CONFIG_RSBAC_UDF)
		rsbac_ta_list_remove(ta_number,
				     process_handles.udf, &tid_p->process);
#endif
		break;

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		/* rsbac_pr_debug(ds, "Removing group ACI\n"); */
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		rsbac_ta_list_remove(ta_number,
				     group_handles.rc, &tid_p->group);
#endif
		break;
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
		rsbac_ta_list_remove(ta_number,
				     netdev_handles.gen, &tid_p->netdev);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     netdev_handles.rc, &tid_p->netdev);
#endif
		break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing nettemp ACI\n");
*/
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.gen, &tid_p->nettemp);
#endif
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.mac, &tid_p->nettemp);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.rc, &tid_p->nettemp);
#endif
#if defined(CONFIG_RSBAC_ACL_NET_OBJ_PROT)
		rsbac_acl_remove_acl(ta_number, T_NETTEMP_NT, tid_p);
		rsbac_acl_remove_acl(ta_number, T_NETTEMP, tid_p);
#endif
		break;

	case T_NETOBJ:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing netobj ACI\n");
*/
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     lnetobj_handles.mac,
				     &tid_p->netobj.sock_p);
		rsbac_ta_list_remove(ta_number,
				     rnetobj_handles.mac,
				     &tid_p->netobj.sock_p);
#endif
#if defined(CONFIG_RSBAC_RC_IND_NET_OBJ)
		rsbac_ta_list_remove(ta_number,
				     lnetobj_handles.rc,
				     &tid_p->netobj.sock_p);
		rsbac_ta_list_remove(ta_number,
				     rnetobj_handles.rc,
				     &tid_p->netobj.sock_p);
#endif
		break;

#endif

	default:
		return -RSBAC_EINVALIDTARGET;
	}
#ifdef CONFIG_RSBAC_XSTATS
	data_race(remove_count[target]++);
#endif
	return error;
}
EXPORT_SYMBOL(rsbac_ta_remove_target);

int rsbac_ta_list_all_dev(rsbac_list_ta_number_t ta_number,
			  struct rsbac_dev_desc_t **id_pp)
{
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, dev_major_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		struct rsbac_dev_desc_t *i_id_p = NULL;
		char *pos = NULL;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC)
		u_int i;
#endif

		if (count > 0) {
			int i_count = 0;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			pos = (char *) *id_pp;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(pos, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
				pos += tmp_count * sizeof(*i_id_p);
			} else
				count = 0;
#if defined(CONFIG_RSBAC_MAC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       mac,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						if (!rsbac_ta_list_exist
						    (ta_number,
						     dev_handles.gen,
						     &i_id_p[i])) {
							memcpy(pos,
							       &i_id_p[i],
							       sizeof
							       (*i_id_p));
							pos +=
							    sizeof
							    (*i_id_p);
							count++;
							i_count--;
						}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
#if defined(CONFIG_RSBAC_RC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_major_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						i_id_p[i].type +=
						    (D_block_major -
						     D_block);
						memcpy(pos, &i_id_p[i],
						       sizeof(*i_id_p));
						pos += sizeof(*i_id_p);
						count++;
						i_count--;
					}
					rsbac_kfree(i_id_p);
				}
			}
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						if (!rsbac_ta_list_exist
						    (ta_number,
						     dev_handles.gen,
						     &i_id_p[i]))
#if defined(CONFIG_RSBAC_MAC)
							if (!rsbac_ta_list_exist(ta_number, dev_handles.mac, &i_id_p[i]))
#endif
								{
									memcpy
									    (pos,
									     &i_id_p
									     [i],
									     sizeof
									     (*i_id_p));
									pos += sizeof(*i_id_p);
									count++;
									i_count--;
								}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

/* Copy new items, of they do not exist. Adjust list counters. */
static int copy_new_uids(rsbac_list_handle_t list,
			 rsbac_list_ta_number_t ta_number,
			 int *count_p,
			 int *i_count_p, rsbac_uid_t * res_id_p)
{
	rsbac_uid_t *i_id_p = NULL;
	rsbac_boolean_t found;
	int tmp_count;
	int i;
	int j;

	if (!list || !count_p || !i_count_p || !res_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!*i_count_p)
		return 0;
/*	rsbac_pr_debug(ds, "list %p, ta_number %u, count %u, "
		       "i_count %u, res_id_p %p, res_id_p[0] %u\n",
		       list, ta_number, *count_p, *i_count_p, res_id_p,
		       res_id_p[0]); */
	tmp_count =
	    rsbac_ta_list_get_all_desc(ta_number, list, (void **) &i_id_p);
	if (tmp_count > 0) {
		if (tmp_count > *i_count_p)
			tmp_count = *i_count_p;
		for (i = 0; i < tmp_count; i++) {
			found = FALSE;
			for (j = 0; j < *count_p; j++) {
				if (res_id_p[j] == i_id_p[i]) {
					found = TRUE;
					break;
				}
			}
			if (found == FALSE) {
				res_id_p[*count_p] = i_id_p[i];
				(*count_p)++;
				(*i_count_p)--;
			}
		}
		rsbac_kfree(i_id_p);
	}
	return 0;
}

#if defined(CONFIG_RSBAC_RES)
/* Copy new items, of they do not exist. Adjust list counters. */
static int copy_new_uids_lol(rsbac_list_handle_t list,
			 rsbac_list_ta_number_t ta_number,
			 int *count_p,
			 int *i_count_p, rsbac_uid_t * res_id_p)
{
	rsbac_uid_t *i_id_p = NULL;
	rsbac_boolean_t found;
	int tmp_count;
	int i;
	int j;

	if (!list || !count_p || !i_count_p || !res_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!*i_count_p)
		return 0;
/*	rsbac_pr_debug(ds, "list %p, ta_number %u, count %u, "
		       "i_count %u, res_id_p %p, res_id_p[0] %u\n",
		       list, ta_number, *count_p, *i_count_p, res_id_p,
		       res_id_p[0]); */
	tmp_count = rsbac_ta_list_lol_get_all_desc(ta_number, list, (void **) &i_id_p);
	if (tmp_count > 0) {
		if (tmp_count > *i_count_p)
			tmp_count = *i_count_p;
		for (i = 0; i < tmp_count; i++) {
			found = FALSE;
			for (j = 0; j < *count_p; j++) {
				if (res_id_p[j] == i_id_p[i]) {
					found = TRUE;
					break;
				}
			}
			if (found == FALSE) {
				res_id_p[*count_p] = i_id_p[i];
				(*count_p)++;
				(*i_count_p)--;
			}
		}
		rsbac_kfree(i_id_p);
	}
	return 0;
}
#endif

int rsbac_ta_list_all_user(rsbac_list_ta_number_t ta_number,
			   rsbac_uid_t ** id_pp)
{
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, user_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_FF)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.ff);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.auth);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.cap);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.jail);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_ta_list_lol_count(ta_number, user_handles.res_min);
	if (tmp_count > 0)
		count += tmp_count;
	tmp_count = rsbac_ta_list_lol_count(ta_number, user_handles.res_max);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_UDF)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.udf);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		if (count > 0) {
			int i_count;
			rsbac_uid_t *i_id_p = NULL;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       user_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(*id_pp, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
			} else
				count = 0;
#if defined(CONFIG_RSBAC_MAC)
			copy_new_uids(user_handles.mac, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_FF)
			copy_new_uids(user_handles.ff, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_RC)
			copy_new_uids(user_handles.rc, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_AUTH)
			copy_new_uids(user_handles.auth, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_CAP)
			copy_new_uids(user_handles.cap, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_JAIL)
			copy_new_uids(user_handles.jail, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_RES)
			copy_new_uids_lol(user_handles.res_min, ta_number, &count,
				      &i_count, *id_pp);
			copy_new_uids_lol(user_handles.res_max, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_UDF)
			copy_new_uids(user_handles.udf, ta_number, &count,
				      &i_count, *id_pp);
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_JAIL)
/* Copy new items, of they do not exist. Adjust list counters. */
static int copy_new_ipcs(rsbac_list_handle_t list,
			 rsbac_list_ta_number_t ta_number,
			 int *count_p,
			 int *i_count_p, struct rsbac_ipc_t * res_id_p)
{
	struct rsbac_ipc_t *i_id_p = NULL;
	rsbac_boolean_t found;
	int tmp_count;
	int i;
	int j;

	if (!list || !count_p || !i_count_p || !res_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!*i_count_p)
		return 0;
/*	rsbac_pr_debug(ds, "list %p, ta_number %u, count %u, "
		      "i_count %u, res_id_p %p, res_id_p[0] %u\n",
		       list, ta_number, *count_p, *i_count_p, res_id_p,
		       res_id_p[0]); */
	tmp_count =
	    rsbac_ta_list_get_all_desc(ta_number, list, (void **) &i_id_p);
	if (tmp_count > 0) {
		if (tmp_count > *i_count_p)
			tmp_count = *i_count_p;
		for (i = 0; i < tmp_count; i++) {
			found = FALSE;
			for (j = 0; j < *count_p; j++) {
				if (!ipc_compare(&res_id_p[j], &i_id_p[i])) {
					found = TRUE;
					break;
				}
			}
			if (found == FALSE) {
				res_id_p[*count_p] = i_id_p[i];
				(*count_p)++;
				(*i_count_p)--;
			}
		}
		rsbac_kfree(i_id_p);
	}
	return 0;
}
#endif

int rsbac_ta_list_all_ipc(rsbac_list_ta_number_t ta_number,
			   struct rsbac_ipc_t ** id_pp)
{
	int count = 0;
#if (defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_JAIL))
	int tmp_count;
#endif

#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif

#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.jail);
	if (tmp_count > 0)
		count += tmp_count;
#endif

	if (id_pp) {
		if (count > 0) {
			int i_count;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			count = 0;

#if defined(CONFIG_RSBAC_MAC)
			copy_new_ipcs(ipc_handles.mac, ta_number, &count,
				      &i_count, *id_pp);
#endif

#if defined(CONFIG_RSBAC_RC)
			copy_new_ipcs(ipc_handles.rc, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_JAIL)
			copy_new_ipcs(ipc_handles.jail, ta_number, &count,
				      &i_count, *id_pp);
#endif

			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

int rsbac_ta_list_all_group(rsbac_list_ta_number_t ta_number,
			    rsbac_gid_t ** id_pp)
{
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, group_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
	if (id_pp) {
		if (count > 0) {
			int i_count;
			rsbac_gid_t *i_id_p = NULL;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       group_handles.
							       rc,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(*id_pp, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
			} else
				count = 0;
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
#else
	return 0;
#endif
}


#ifdef CONFIG_RSBAC_NET_DEV
int rsbac_ta_net_list_all_netdev(rsbac_list_ta_number_t ta_number,
				 rsbac_netdev_id_t ** id_pp)
{
	int count = 0;
	int tmp_count;

#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	tmp_count = rsbac_ta_list_count(ta_number, netdev_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, netdev_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		rsbac_netdev_id_t *i_id_p = NULL;
		char *pos = NULL;
#if defined(CONFIG_RSBAC_RC)
		u_int i;
#endif

		if (count > 0) {
			int i_count = 0;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			pos = (char *) *id_pp;
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       netdev_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(pos, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
				pos += tmp_count * sizeof(*i_id_p);
			} else
				count = 0;
#endif
#if defined(CONFIG_RSBAC_RC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       netdev_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
						if (!rsbac_ta_list_exist
						    (ta_number,
						     netdev_handles.gen,
						     &i_id_p[i]))
#endif
						{
							memcpy(pos,
							       &i_id_p[i],
							       sizeof
							       (*i_id_p));
							pos +=
							    sizeof
							    (*i_id_p);
							count++;
							i_count--;
						}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
/* Get a template id from a net description */
inline int rsbac_net_get_id(rsbac_list_ta_number_t ta_number,
		     struct rsbac_net_description_t *desc_p,
		     rsbac_net_temp_id_t * id_p)
{
	if (!rsbac_initialized)
		return -RSBAC_ENOTINITIALIZED;
	if (!id_p || !desc_p)
		return -RSBAC_EINVALIDPOINTER;
	if (rsbac_ta_list_get_desc(ta_number,
				   net_temp_handle,
				   id_p, desc_p, rsbac_net_compare_data)
	    )
		*id_p = RSBAC_NET_UNKNOWN;
	return 0;
}

/* get the template ids for a netobj */
/* set *_temp_p to NULL, if you do not need it */
int rsbac_ta_net_lookup_templates(rsbac_list_ta_number_t ta_number,
				  struct rsbac_net_obj_desc_t *netobj_p,
				  rsbac_net_temp_id_t * local_temp_p,
				  rsbac_net_temp_id_t * remote_temp_p)
{
	struct rsbac_net_description_t *rsbac_net_desc_p;
	int err = 0;
	struct net_device *dev;

	if (!netobj_p || !netobj_p->sock_p || !netobj_p->sock_p->sk
	    || !netobj_p->sock_p->ops)
		return -RSBAC_EINVALIDPOINTER;
	if (!local_temp_p && !remote_temp_p)
		return -RSBAC_EINVALIDVALUE;

	rsbac_net_desc_p = rsbac_kmalloc_unlocked(sizeof(*rsbac_net_desc_p));
	if (!rsbac_net_desc_p)
		return -RSBAC_ENOMEM;

	rsbac_net_desc_p->address_family = netobj_p->sock_p->ops->family;
	rsbac_net_desc_p->type = netobj_p->sock_p->type;
	rsbac_net_desc_p->protocol = netobj_p->sock_p->sk->sk_protocol;
	if (netobj_p->sock_p->sk->sk_bound_dev_if) {
		dev = dev_get_by_index(&init_net, netobj_p->sock_p->sk->
				     sk_bound_dev_if);
		if (dev) {
			strcpy(rsbac_net_desc_p->netdev, dev->name);
			dev_put(dev);
		} else
			rsbac_net_desc_p->netdev[0] = RSBAC_NET_UNKNOWN;
	} else
		rsbac_net_desc_p->netdev[0] = RSBAC_NET_UNKNOWN;
	if (local_temp_p) {
		switch (rsbac_net_desc_p->address_family) {
		case AF_INET:
			if (netobj_p->local_addr) {
				struct sockaddr_in *addr =
				    netobj_p->local_addr;

				rsbac_net_desc_p->address =
				    &addr->sin_addr.s_addr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(addr->sin_port);
			} else {
				rsbac_net_desc_p->address =
				    &inet_sk(netobj_p->sock_p->sk)->
				    inet_rcv_saddr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    inet_sk(netobj_p->sock_p->sk)->inet_num;
			}
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6:
			if (netobj_p->local_addr) {
				struct sockaddr_in6 *addr =
				    netobj_p->local_addr;

				rsbac_net_desc_p->address =
				    &addr->sin6_addr.s6_addr;
				rsbac_net_desc_p->address_len =
				    RSBAC_NET_INET6_ADDR_SIZE;
				rsbac_net_desc_p->port =
				    ntohs(addr->sin6_port);
				rsbac_pr_debug(ds_net, "rsbac_ta_net_lookup_templates(): local from local_addr: [%pI6c]:%u!\n", rsbac_net_desc_p->address, rsbac_net_desc_p->port);
			} else {
				rsbac_net_desc_p->address =
				    &inet6_rcv_saddr(netobj_p->sock_p->sk)->s6_addr;
				rsbac_net_desc_p->address_len =
				    RSBAC_NET_INET6_ADDR_SIZE;
				rsbac_net_desc_p->port =
				    inet_sk(netobj_p->sock_p->sk)->inet_num;
				rsbac_pr_debug(ds_net, "rsbac_ta_net_lookup_templates(): local from sk: [%pI6c]:%u!\n", rsbac_net_desc_p->address, rsbac_net_desc_p->port);

			}
/*
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
*/
			break;
#endif
		case AF_UNIX:
			rsbac_printk(KERN_WARNING "rsbac_ta_net_lookup_templates(): unsupported family AF_UNIX, should be target UNIXSOCK or IPC-anonunix\n");
			BUG();
			return -RSBAC_EINVALIDTARGET;

		default:
			rsbac_net_desc_p->address = NULL;
			rsbac_net_desc_p->port = RSBAC_NET_UNKNOWN;
		}
		if ((err = rsbac_net_get_id(ta_number, rsbac_net_desc_p,
			local_temp_p))) {
			*local_temp_p = 0;
			rsbac_printk(KERN_WARNING "rsbac_net_lookup_templates(): rsbac_net_get_id for local returned error %u\n",
				     err);
		}
		if (rsbac_net_desc_p->address_family == AF_INET || rsbac_net_desc_p->address_family == AF_INET6)
			rsbac_pr_debug(ds_net,
				       "user %u temp id for local is %u\n",
				       __kuid_val(current_uid()), *local_temp_p);
	}
	if (remote_temp_p) {
		switch (rsbac_net_desc_p->address_family) {
		case AF_INET:
			if (netobj_p->remote_addr) {
				struct sockaddr_in *addr =
				    netobj_p->remote_addr;

				rsbac_net_desc_p->address =
				    &addr->sin_addr.s_addr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(addr->sin_port);
			} else {
				rsbac_net_desc_p->address =
				    &inet_sk(netobj_p->sock_p->sk)->inet_daddr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(inet_sk(netobj_p->sock_p->sk)->
					  inet_dport);
			}
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6:
			if (netobj_p->remote_addr) {
				struct sockaddr_in6 *addr =
				    netobj_p->remote_addr;

				rsbac_net_desc_p->address =
				    &addr->sin6_addr.s6_addr;
				rsbac_net_desc_p->address_len =
				    RSBAC_NET_INET6_ADDR_SIZE;
				rsbac_net_desc_p->port =
				    ntohs(addr->sin6_port);
				rsbac_pr_debug(ds_net, "rsbac_ta_net_lookup_templates(): remote from remote_addr: [%pI6c]:%u!\n", rsbac_net_desc_p->address, rsbac_net_desc_p->port);
			} else {
				rsbac_net_desc_p->address =
				    &netobj_p->sock_p->sk->sk_v6_daddr.s6_addr;
				rsbac_net_desc_p->address_len =
				    RSBAC_NET_INET6_ADDR_SIZE;
				rsbac_net_desc_p->port =
				    inet_sk(netobj_p->sock_p->sk)->inet_num;
				rsbac_pr_debug(ds_net, "rsbac_ta_net_lookup_templates(): remote from sk: [%pI6c]:%u!\n", rsbac_net_desc_p->address, rsbac_net_desc_p->port);
			}
/*
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
*/
			break;
#endif
		case AF_UNIX:
			rsbac_printk(KERN_WARNING "rsbac_ta_net_lookup_templates(): unsupported family AF_UNIX, should be target UNIXSOCK or IPC-anonunix\n");
			return -RSBAC_EINVALIDTARGET;

		default:
			rsbac_net_desc_p->address = NULL;
			rsbac_net_desc_p->address_len = 0;
			rsbac_net_desc_p->port = RSBAC_NET_UNKNOWN;
		}
		if ((err =
		     rsbac_net_get_id(ta_number, rsbac_net_desc_p,
				      remote_temp_p))) {
			*remote_temp_p = 0;
			rsbac_printk(KERN_WARNING "rsbac_net_lookup_templates(): rsbac_net_get_id for remote returned error %u\n",
				     err);
		}
		if (rsbac_net_desc_p->address_family == AF_INET || rsbac_net_desc_p->address_family == AF_INET6)
			rsbac_pr_debug(ds_net,
				       "user %u temp id for remote is %u\n",
				       __kuid_val(current_uid()), *remote_temp_p);
	}
	rsbac_kfree(rsbac_net_desc_p);
	return 0;
}

int rsbac_ta_net_template_exists(rsbac_list_ta_number_t ta_number,
	rsbac_net_temp_id_t id)
{
  return rsbac_ta_list_exist(ta_number, net_temp_handle, &id);
}

int rsbac_ta_net_template(rsbac_list_ta_number_t ta_number,
			  enum rsbac_net_temp_syscall_t call,
			  rsbac_net_temp_id_t id,
			  union rsbac_net_temp_syscall_data_t *data_p)
{
	struct rsbac_net_temp_data_t int_data;
	int err;

	memset(&int_data, 0, sizeof(int_data));
	int_data.address_family = AF_MAX;
	int_data.type = RSBAC_NET_ANY;
	int_data.protocol = RSBAC_NET_ANY;
	strcpy(int_data.name, "DEFAULT");

	switch (call) {
	case NTS_new_template:
	case NTS_check_id:
		break;
	case NTS_copy_template:
		err = rsbac_ta_list_get_data_ttl(ta_number,
						 net_temp_handle,
						 NULL,
						 &data_p->id, &int_data);
		if (err)
			return err;
		break;
	default:
		err = rsbac_ta_list_get_data_ttl(ta_number,
						 net_temp_handle,
						 NULL, &id, &int_data);
		if (err)
			return err;
	}
	/* get data values from user space */
	switch (call) {
	case NTS_set_address:
		if(int_data.address_family == AF_INET) {
			int i;

			if(data_p->address.inet.nr_addr > RSBAC_NET_NR_INET_ADDR)
				return -RSBAC_EINVALIDVALUE;
			for(i=0; i<data_p->address.inet.nr_addr; i++)
				if(data_p->address.inet.valid_bits[i] > 32)
					return -RSBAC_EINVALIDVALUE;
			memcpy(&int_data.address.inet, &data_p->address.inet,
				sizeof(int_data.address.inet));
		} else if(int_data.address_family == AF_INET6) {
			int i;

			if(data_p->address.inet6.nr_addr > RSBAC_NET_NR_INET6_ADDR)
				return -RSBAC_EINVALIDVALUE;
			for(i=0; i<data_p->address.inet6.nr_addr; i++)
				if(data_p->address.inet6.valid_bits[i] > 128)
					return -RSBAC_EINVALIDVALUE;
			rsbac_pr_debug(ds_net, "rsbac_ta_net_template: template %u, set %u INET6 addresses\n", id, data_p->address.inet6.nr_addr);
			for(i=0; i<data_p->address.inet6.nr_addr; i++)
				rsbac_pr_debug(ds_net, "rsbac_ta_net_template: template %u, address %u is %pI6c/%u\n", id, i, &data_p->address.inet6.addr[i * RSBAC_NET_INET6_ADDR_SIZE], data_p->address.inet6.valid_bits[i]);
			memcpy(&int_data.address.inet6, &data_p->address.inet6,
				sizeof(int_data.address.inet6));
		} else {
			memcpy(&int_data.address.other, &data_p->address.other,
				sizeof(int_data.address.other));
		}
		return rsbac_ta_list_add_ttl(ta_number, net_temp_handle, 0,
					     &id, &int_data);
	case NTS_set_address_family:
		if(int_data.address_family != data_p->address_family) {
			int_data.address_family = data_p->address_family;
			memset(&int_data.address, 0, sizeof(int_data.address));
		}
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_type:
		int_data.type = data_p->type;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_protocol:
		int_data.protocol = data_p->protocol;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_netdev:
		strncpy(int_data.netdev, data_p->netdev, RSBAC_IFNAMSIZ);
		int_data.netdev[RSBAC_IFNAMSIZ] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_ports:
		memcpy(&int_data.ports, &data_p->ports,
			sizeof(int_data.ports));
		if(int_data.ports.nr_ports > RSBAC_NET_NR_PORTS)
			return -RSBAC_EINVALIDVALUE;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_name:
		strncpy(int_data.name, data_p->name,
			RSBAC_NET_TEMP_NAMELEN - 1);
		int_data.name[RSBAC_NET_TEMP_NAMELEN - 1] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_new_template:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id))
			return -RSBAC_EEXISTS;
		strncpy(int_data.name, data_p->name,
			RSBAC_NET_TEMP_NAMELEN - 1);
		int_data.name[RSBAC_NET_TEMP_NAMELEN - 1] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_copy_template:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_delete_template:
		return rsbac_ta_list_remove(ta_number, net_temp_handle,
					    &id);
	case NTS_check_id:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id)) {
			data_p->id = id;
			return 0;
		} else
			return -RSBAC_ENOTFOUND;
	case NTS_get_address:
		memcpy(&data_p->address, &int_data.address,
		       sizeof(int_data.address));
		return 0;
	case NTS_get_address_family:
		data_p->address_family = int_data.address_family;
		return 0;
	case NTS_get_type:
		data_p->type = int_data.type;
		return 0;
	case NTS_get_protocol:
		data_p->protocol = int_data.protocol;
		return 0;
	case NTS_get_netdev:
		strncpy(data_p->netdev, int_data.netdev, RSBAC_IFNAMSIZ);
		return 0;
	case NTS_get_ports:
		memcpy(&data_p->ports, &int_data.ports,
		       sizeof(int_data.ports));
		return 0;
	case NTS_get_name:
		strcpy(data_p->name, int_data.name);
		return 0;

	default:
		return -RSBAC_EINVALIDREQUEST;
	}
}

int rsbac_ta_net_list_all_template(rsbac_list_ta_number_t ta_number,
				   rsbac_net_temp_id_t ** id_pp)
{
	if (id_pp)
		return rsbac_ta_list_get_all_desc(ta_number,
						  net_temp_handle,
						  (void **) id_pp);
	else
		return rsbac_ta_list_count(ta_number, net_temp_handle);
}

int rsbac_ta_net_template_exist(rsbac_list_ta_number_t ta_number,
				rsbac_net_temp_id_t temp)
{
	return rsbac_ta_list_exist(ta_number, net_temp_handle, &temp);
}

int rsbac_net_remote_request(enum rsbac_adf_request_t request)
{
	switch (request) {
	case R_SEND:
	case R_RECEIVE:
	case R_READ:
	case R_WRITE:
	case R_ACCEPT:
	case R_CONNECT:
		return TRUE;

	default:
		return FALSE;
	}
}

#endif				/* NET_OBJ */

#if defined(CONFIG_RSBAC_JAIL)
static int rsbac_jail_exists_compare(void * data1, void * data2)
{
  struct rsbac_jail_process_aci_t * aci_p = data1;

  return memcmp(&aci_p->id, data2, sizeof(rsbac_jail_id_t));
}

rsbac_boolean_t rsbac_jail_exists(rsbac_jail_id_t jail_id)
{
	rsbac_pid_t pid;

	if(!rsbac_ta_list_get_desc(0,
				process_handles.jail,
				&pid,
				&jail_id,
				rsbac_jail_exists_compare))
		return TRUE;
	else
		return FALSE;
}
#endif

#if defined(CONFIG_RSBAC_UDF)
EXPORT_SYMBOL(rsbac_udf_flush_cache);
int rsbac_udf_flush_cache(void)
{
#if defined(CONFIG_RSBAC_UDF_CACHE)
	struct rsbac_device_list_head_t *head_p;
	struct rsbac_device_list_item_t *device_p;
	u_int i;
	int srcu_idx;

	for (i = 0; i < BIT(CONFIG_RSBAC_DEVICE_LIST_HASH_BITS); i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		head_p = srcu_dereference(device_head_p[i], &device_list_srcu[i]);
		device_p = srcu_dereference(head_p->head, &device_list_srcu[i]);
		while (device_p) {
			rsbac_list_remove_all(device_p->handles.udfc);
			device_p = srcu_dereference(device_p->next, &device_list_srcu[i]);
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
#endif
	return 0;
}
#endif

void rsbac_flags_set(unsigned long int rsbac_flags)
{
}

void rsbac_delayed_kfree(void * data, rsbac_time_t ttl)
{
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	struct rsbac_delayed_kfree_list_t * new_item;

	if (!data || !delayed_kfree_item_slab)
		return;
//	rsbac_printk(KERN_DEBUG "rsbac_delayed_kfree: called with data %p ttl %u\n", data, ttl);
	new_item = rsbac_smalloc(delayed_kfree_item_slab);
	if (!new_item) {
		rsbac_printk(KERN_WARNING "rsbac_delayed_kfree: failed to allocate memory\n");
		return;
	}
	new_item->next = NULL;
	new_item->data = data;
	new_item->max_age = RSBAC_CURRENT_TIME + ttl;
	spin_lock(&delayed_kfree_lock);
	if(delayed_kfree_last) {
		delayed_kfree_last->next = new_item;
		delayed_kfree_last = new_item;
	} else
		delayed_kfree_last = delayed_kfree_first = new_item;
#ifdef CONFIG_RSBAC_XSTATS
	data_race(delayed_kfree_count++);
	data_race(delayed_kfree_used++);
#endif
	spin_unlock(&delayed_kfree_lock);
#endif
}
