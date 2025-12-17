/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2025:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Generic lists for all parts         */
/* Last modified: 17/Dec/2025          */
/************************************* */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/module.h>
#ifdef CONFIG_RSBAC_LIST_TRANS_RANDOM_TA
#include <linux/random.h>
#endif
#include <linux/seq_file.h>
#ifndef CONFIG_RSBAC_NO_WRITE
#include <linux/mount.h>
#endif
#include <linux/srcu.h>
#include <linux/hash.h>

#include <rsbac/types.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/debug.h>
#include <rsbac/adf.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/proc_fs.h>
#include <rsbac/rkmem.h>
#include <rsbac/lists.h>
#include <rsbac/gen_lists.h>

/********************/
/* Global Variables */
/********************/

static struct rsbac_list_reg_head_t reg_head;
static struct rsbac_list_lol_reg_head_t lol_reg_head;
static rsbac_boolean_t list_initialized = FALSE;
static struct srcu_struct reg_list_srcu;
static struct srcu_struct lol_reg_list_srcu;

static struct kmem_cache * reg_item_slab = NULL;
static struct kmem_cache * lol_reg_item_slab = NULL;

static struct lock_class_key list_lock_class;
static struct lock_class_key hash_lock_class;

static u_int rsbac_list_max_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;

#ifdef CONFIG_RSBAC_LIST_TRANS
static struct rsbac_list_reg_item_t *ta_handle = NULL;
static DEFINE_SPINLOCK(ta_lock);
static rsbac_boolean_t ta_committing = FALSE;
DECLARE_WAIT_QUEUE_HEAD(ta_wait);
#ifndef CONFIG_RSBAC_LIST_TRANS_RANDOM_TA
rsbac_list_ta_number_t ta_next = 1;
#endif
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
static int do_forget(rsbac_list_ta_number_t ta_number);
#endif

#ifdef CONFIG_RSBAC_AUTO_WRITE
static rsbac_time_t next_rehash = 0;
#endif

static u_int rsbac_list_read_errors = 0;

#ifdef CONFIG_RSBAC_LIST_STATS
static __u64 rcu_free_calls = 0;
static __u64 rcu_free_item_chain_calls = 0;
static __u64 rcu_free_lol_calls = 0;
static __u64 rcu_free_lol_sub_calls = 0;
static __u64 rcu_free_lol_item_chain_calls = 0;
static __u64 rcu_free_lol_subitem_chain_calls = 0;
static __u64 rcu_free_do_cleanup_calls = 0;
static __u64 rcu_free_do_cleanup_lol_calls = 0;
static __u64 rcu_free_callback_calls = 0;
static __u64 rcu_free_callback_lol_calls = 0;
static __u32 max_rcu_callback_count = 0;
static __u64 rcu_free_alloc_failed = 0;
static __u64 rcu_free_lol_alloc_failed = 0;
static __u64 rcu_free_lol_sub_alloc_failed = 0;
static __u64 rcu_rate_reached_count = 0;

#ifndef CONFIG_TINY_RCU
unsigned long rcu_exp_batches_completed(void);
#endif
#endif

/* Limit RCU callback calls to RCURATE per second, switch to sync when exceeded */
#if CONFIG_RSBAC_RCU_RATE < 0
#define RCURATE 0
#else
#if CONFIG_RSBAC_RCU_RATE > 1000
#define RCURATE 1000
#else
#define RCURATE CONFIG_RSBAC_RCU_RATE
#endif
#endif
u_int rsbac_list_rcu_rate = RCURATE;
static u_int rcu_callback_count = 0;
static struct timer_list rcu_rate_timer;

static struct kmem_cache * rcu_free_item_slab = NULL;
static struct kmem_cache * rcu_free_head_slab = NULL;
static struct kmem_cache * rcu_free_head_lol_slab = NULL;

/*********************************/
/* Data Structures               */
/*********************************/

/* RCU garbage collector */

/* Call spinlocked */
static inline struct rsbac_list_rcu_free_head_t *
	get_rcu_free(struct rsbac_list_reg_item_t * list, u_int hash)
{
	if (list->hashed[hash].rcu_free) {
		struct rsbac_list_rcu_free_head_t * rcu_free;

		rcu_free = list->hashed[hash].rcu_free;
		list->hashed[hash].rcu_free = NULL;
		return rcu_free;
	} else
		return NULL;
}

/* Call spinlocked */
static inline struct rsbac_list_rcu_free_head_lol_t *
	get_rcu_free_lol(struct rsbac_list_lol_reg_item_t * list, u_int hash)
{
	if (list->hashed[hash].rcu_free) {
		struct rsbac_list_rcu_free_head_lol_t * rcu_free;

		rcu_free = list->hashed[hash].rcu_free;
		list->hashed[hash].rcu_free = NULL;
		return rcu_free;
	} else
		return NULL;
}

/* Call spinlocked */
static struct rsbac_list_rcu_free_head_t *
	create_rcu_free(struct rsbac_list_reg_item_t * list, u_int hash)
{
	/* Just to be sure */
	if (unlikely(!list))
		return NULL;
	/* Exists, all fine */
	if (list->hashed[hash].rcu_free)
		return list->hashed[hash].rcu_free;

	list->hashed[hash].rcu_free = rsbac_smalloc_clear(rcu_free_head_slab);
	if (unlikely(!list->hashed[hash].rcu_free))
		return NULL;
	list->hashed[hash].rcu_free->slab = list->slab;
	return list->hashed[hash].rcu_free;
}

/* Call spinlocked */
static struct rsbac_list_rcu_free_head_lol_t *
	create_rcu_free_lol(struct rsbac_list_lol_reg_item_t * list, u_int hash)
{
	/* Just to be sure */
	if (unlikely(!list))
		return NULL;
	/* Exists, all fine */
	if (list->hashed[hash].rcu_free)
		return list->hashed[hash].rcu_free;

	list->hashed[hash].rcu_free = rsbac_smalloc_clear(rcu_free_head_lol_slab);
	if (unlikely(!list->hashed[hash].rcu_free))
		return NULL;
	list->hashed[hash].rcu_free->slab = list->slab;
	list->hashed[hash].rcu_free->subslab = list->subslab;
	return list->hashed[hash].rcu_free;
}

/* Call spinlocked */
static void rcu_free(struct rsbac_list_reg_item_t * list, u_int hash, void * mem)
{
	struct rsbac_list_rcu_free_item_t * rcu_item;

	if (unlikely(!create_rcu_free(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free(): cannot allocate rcu_free_head for list %s, loosing item %p!\n",
			     list->name, mem);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_calls++);
#endif
	rcu_item = rsbac_smalloc(rcu_free_item_slab);
	if (likely(rcu_item)) {
		rcu_item->mem = mem;
		rcu_item->next = list->hashed[hash].rcu_free->head;
		list->hashed[hash].rcu_free->head = rcu_item;
	} else {
		rsbac_printk(KERN_WARNING "rcu_free(): cannot allocate rcu_free for list %s, loosing item %p!\n",
			     list->name, mem);
		rcu_callback_count = rsbac_list_rcu_rate;
#ifdef CONFIG_RSBAC_LIST_STATS
		data_race(rcu_free_alloc_failed++);
#endif
	}
}

/* Call spinlocked */
static void rcu_free_lol(struct rsbac_list_lol_reg_item_t * list, u_int hash, void * mem)
{
	struct rsbac_list_rcu_free_item_t * rcu_item;

	if (unlikely(!create_rcu_free_lol(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free_lol(): cannot allocate rcu_free_head for list of lists %s, loosing item %p!\n",
			     list->name, mem);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_lol_calls++);
#endif
	rcu_item = rsbac_smalloc(rcu_free_item_slab);
	if (likely(rcu_item)) {
		rcu_item->mem = mem;
		rcu_item->next = list->hashed[hash].rcu_free->head;
		list->hashed[hash].rcu_free->head = rcu_item;
	} else {
		rsbac_printk(KERN_WARNING "rcu_free_lol(): cannot allocate rcu_free for list of lists %s, loosing item %p!\n",
			     list->name, mem);
		rcu_callback_count = rsbac_list_rcu_rate;
#ifdef CONFIG_RSBAC_LIST_STATS
		data_race(rcu_free_lol_alloc_failed++);
#endif
	}
}

/* Call spinlocked */
static void rcu_free_lol_sub(struct rsbac_list_lol_reg_item_t * list, u_int hash, void * mem)
{
	struct rsbac_list_rcu_free_item_t * rcu_item;

	if (unlikely(!create_rcu_free_lol(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free_lol_sub(): cannot allocate rcu_free_head for list of lists %s, loosing subitem %p!\n",
			     list->name, mem);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_lol_calls++);
#endif
	rcu_item = rsbac_smalloc(rcu_free_item_slab);
	if (likely(rcu_item)) {
		rcu_item->mem = mem;
		rcu_item->next = list->hashed[hash].rcu_free->subhead;
		list->hashed[hash].rcu_free->subhead = rcu_item;
	} else {
		rsbac_printk(KERN_WARNING "rcu_free_lol_sub(): cannot allocate rcu_free for list of lists %s, loosing subitem %p!\n",
			     list->name, mem);
		rcu_callback_count = rsbac_list_rcu_rate;
#ifdef CONFIG_RSBAC_LIST_STATS
		data_race(rcu_free_lol_sub_alloc_failed++);
#endif
	}
}

/* Call spinlocked */
static void rcu_free_item_chain(struct rsbac_list_reg_item_t * list,
				u_int hash,
				struct rsbac_list_item_t * item_chain)
{
	if (!item_chain)
		return;
	if (unlikely(!create_rcu_free(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free_item_chain(): cannot allocate rcu_free_head for list %s, loosing chain %p!\n",
			     list->name, item_chain);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_item_chain_calls++);
#endif
	if (!list->hashed[hash].rcu_free->item_chain) {
		list->hashed[hash].rcu_free->item_chain = item_chain;
	} else { 
		while (item_chain) {
			rcu_free(list, hash, item_chain);
			item_chain = item_chain->next;
		}
	}
}

/* Call spinlocked */
static void rcu_free_lol_subitem_chain(struct rsbac_list_lol_reg_item_t * list,
				u_int hash,
				struct rsbac_list_item_t * subitem_chain)
{
	if (!subitem_chain)
		return;
	if (unlikely(!create_rcu_free_lol(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free_lol_subitem_chain(): cannot allocate rcu_free_head for list of lists %s, loosing subchain %p!\n",
			     list->name, subitem_chain);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_lol_subitem_chain_calls++);
#endif
	if (!list->hashed[hash].rcu_free->lol_item_subchain) {
		list->hashed[hash].rcu_free->lol_item_subchain = subitem_chain;
	} else { 
		while (subitem_chain) {
			rcu_free_lol_sub(list, hash, subitem_chain);
			subitem_chain = subitem_chain->next;
		}
	}
}

/* Call spinlocked */
static void rcu_free_lol_item_chain(struct rsbac_list_lol_reg_item_t * list,
				u_int hash,
				struct rsbac_list_lol_item_t * lol_item_chain)
{
	if (!lol_item_chain)
		return;
	if (unlikely(!create_rcu_free_lol(list, hash))) {
		rsbac_printk(KERN_WARNING "rcu_free_lol_item_chain(): cannot allocate rcu_free_head for list of lists %s, loosing chain %p!\n",
			     list->name, lol_item_chain);
		return;
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_lol_item_chain_calls++);
#endif
	if (!list->hashed[hash].rcu_free->lol_item_chain) {
		list->hashed[hash].rcu_free->lol_item_chain = lol_item_chain;
	} else { 
		struct rsbac_list_item_t * sub_item;

		while (lol_item_chain) {
			sub_item = lol_item_chain->head;
			while (sub_item) {
				rcu_free_lol_sub(list, hash, sub_item);
				sub_item = sub_item->next;
			}
			rcu_free_lol(list, hash, lol_item_chain);
			lol_item_chain = lol_item_chain->next;
		}
	}
}

/* Call unlocked */
static void rcu_free_do_cleanup(struct rsbac_list_rcu_free_head_t * rcu_head)
{
	struct rsbac_list_rcu_free_item_t * rcu_item;
	struct rsbac_list_rcu_free_item_t * rcu_next_item;
	struct rsbac_list_item_t * item_chain;
	struct rsbac_list_item_t * item_chain_next;

	if (!rcu_head)
		return;
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_do_cleanup_calls++);
#endif
	rcu_item = rcu_head->head;
	if (rcu_head->slab) {
		while (rcu_item) {
			rsbac_sfree(rcu_head->slab, rcu_item->mem);
			rcu_next_item = rcu_item->next;
			rsbac_sfree(rcu_free_item_slab, rcu_item);
			rcu_item = rcu_next_item;
		}
		item_chain = rcu_head->item_chain;
		while (item_chain) {
			item_chain_next = item_chain->next;
			rsbac_sfree(rcu_head->slab, item_chain);
			item_chain = item_chain_next;
		}
	} else {
		while (rcu_item) {
			rsbac_kfree(rcu_item->mem);
			rcu_next_item = rcu_item->next;
			rsbac_sfree(rcu_free_item_slab, rcu_item);
			rcu_item = rcu_next_item;
		}
		item_chain = rcu_head->item_chain;
		while (item_chain) {
			item_chain_next = item_chain->next;
			rsbac_kfree(item_chain);
			item_chain = item_chain_next;
		}
	}
	rsbac_sfree(rcu_free_head_slab, rcu_head);
}

/* Call unlocked */
static void rcu_free_do_cleanup_lol(struct rsbac_list_rcu_free_head_lol_t * rcu_head)
{
	struct rsbac_list_rcu_free_item_t * rcu_item;
	struct rsbac_list_rcu_free_item_t * rcu_next_item;
	struct rsbac_list_lol_item_t * lol_item_chain;
	struct rsbac_list_lol_item_t * lol_item_chain_next;
	struct rsbac_list_item_t * lol_item_subchain;
	struct rsbac_list_item_t * lol_item_subchain_next;

	if (!rcu_head)
		return;
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_do_cleanup_lol_calls++);
#endif
	rcu_item = rcu_head->head;
	if (rcu_head->slab) {
		while (rcu_item) {
			rsbac_sfree(rcu_head->slab, rcu_item->mem);
			rcu_next_item = rcu_item->next;
			rsbac_sfree(rcu_free_item_slab, rcu_item);
			rcu_item = rcu_next_item;
		}
		rcu_item = rcu_head->subhead;
		while (rcu_item) {
			rsbac_sfree(rcu_head->subslab, rcu_item->mem);
			rcu_next_item = rcu_item->next;
			rsbac_sfree(rcu_free_item_slab, rcu_item);
			rcu_item = rcu_next_item;
		}
		lol_item_chain = rcu_head->lol_item_chain;
		while (lol_item_chain) {
			lol_item_subchain = lol_item_chain->head;
			while (lol_item_subchain) {
				lol_item_subchain_next = lol_item_subchain->next;
				rsbac_sfree(rcu_head->subslab, lol_item_subchain);
				lol_item_subchain = lol_item_subchain_next;
			}
			lol_item_chain_next = lol_item_chain->next;
			rsbac_sfree(rcu_head->slab, lol_item_chain);
			lol_item_chain = lol_item_chain_next;
		}
		lol_item_subchain = rcu_head->lol_item_subchain;
		while (lol_item_subchain) {
			lol_item_subchain_next = lol_item_subchain->next;
			rsbac_sfree(rcu_head->subslab, lol_item_subchain);
			lol_item_subchain = lol_item_subchain_next;
		}
	} else {
		while (rcu_item) {
			rsbac_kfree(rcu_item->mem);
			rcu_next_item = rcu_item->next;
			rsbac_sfree(rcu_free_item_slab, rcu_item);
			rcu_item = rcu_next_item;
		}
		lol_item_chain = rcu_head->lol_item_chain;
		while (lol_item_chain) {
			lol_item_subchain = lol_item_chain->head;
			while (lol_item_subchain) {
				lol_item_subchain_next = lol_item_subchain->next;
				rsbac_kfree(lol_item_subchain);
				lol_item_subchain = lol_item_subchain_next;
			}
			lol_item_chain_next = lol_item_chain->next;
			rsbac_kfree(lol_item_chain);
			lol_item_chain = lol_item_chain_next;
		}
		lol_item_subchain = rcu_head->lol_item_subchain;
		while (lol_item_subchain) {
			lol_item_subchain_next = lol_item_subchain->next;
			rsbac_kfree(lol_item_subchain);
			lol_item_subchain = lol_item_subchain_next;
		}
	}
	rsbac_sfree(rcu_free_head_lol_slab, rcu_head);
}

/* RCU callback, do not call directly. Called unlocked by RCU. */
static void rcu_free_callback(struct rcu_head *rp)
{
	if (unlikely(!rp))
		return;
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_callback_calls++);
#endif
	rcu_free_do_cleanup((struct rsbac_list_rcu_free_head_t *) rp);
}

/* RCU callback, do not call directly. Called unlocked by RCU. */
static void rcu_free_callback_lol(struct rcu_head *rp)
{
	if (unlikely(!rp))
		return;
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(rcu_free_callback_lol_calls++);
#endif
	rcu_free_do_cleanup_lol((struct rsbac_list_rcu_free_head_lol_t *) rp);
}

/* Call unlocked */
static void do_call_rcu(struct rsbac_list_rcu_free_head_t * rcu_head)
{
	if (rcu_head) {
		data_race(rcu_callback_count++);
		call_rcu(&rcu_head->rcu, rcu_free_callback);
	}
}
/* Call unlocked */
static void do_call_rcu_lol(struct rsbac_list_rcu_free_head_lol_t * rcu_head)
{
	if (rcu_head) {
		data_race(rcu_callback_count++);
		call_rcu(&rcu_head->rcu, rcu_free_callback_lol);
	}
}

/* Call unlocked */
static void do_sync_rcu(struct rsbac_list_rcu_free_head_t * rcu_head)
{
	if (rcu_head) {
		data_race(rcu_callback_count++);
		if (rcu_callback_count < rsbac_list_rcu_rate)
			call_rcu(&rcu_head->rcu, rcu_free_callback);
		else {
			synchronize_rcu();
			rcu_free_do_cleanup(rcu_head);
#ifdef CONFIG_RSBAC_LIST_STATS
			data_race(rcu_rate_reached_count++);
#endif
		}
	}
}

/* Call unlocked */
static void do_sync_rcu_lol(struct rsbac_list_rcu_free_head_lol_t * rcu_head)
{
	if (rcu_head) {
		data_race(rcu_callback_count++);
		if (rcu_callback_count < rsbac_list_rcu_rate)
			call_rcu(&rcu_head->rcu, rcu_free_callback_lol);
		else {
			synchronize_rcu();
			rcu_free_do_cleanup_lol(rcu_head);
#ifdef CONFIG_RSBAC_LIST_STATS
			data_race(rcu_rate_reached_count++);
#endif
		}
	}
}

/* List handling */
/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_compare(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* NULL or not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_memcmp(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static struct rsbac_list_item_t *lookup_item(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	if (unlikely(!list || !desc || !hashed))
		return NULL;

	if (list->compare)
		return lookup_item_compare(list, hashed, hash, desc);
	else
		return lookup_item_memcmp(list, hashed, hash, desc);
}

/* Call spinlocked */
static inline struct rsbac_list_item_t *lookup_item_compare_locked(
	struct rsbac_list_reg_item_t *list, u_int hash, void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !desc || !list->compare))
		return NULL;

	curr = list->hashed[hash].curr;
	if (!curr) {
		curr = list->hashed[hash].head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].curr, curr);
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* NULL or not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static inline struct rsbac_list_item_t *lookup_item_memcmp_locked(struct
						    rsbac_list_reg_item_t
						    *list, u_int hash, void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !desc))
		return NULL;

	curr = list->hashed[hash].curr;
	if (!curr) {
		curr = list->hashed[hash].head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].curr, curr);
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_item_t *lookup_item_locked(struct rsbac_list_reg_item_t
					     *list, u_int hash, void *desc)
{
	if (unlikely(!list || !desc))
		return NULL;

	if (list->compare)
		return lookup_item_compare_locked(list, hash, desc);
	else
		return lookup_item_memcmp_locked(list, hash, desc);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_compare(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
 	void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].ta_curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].ta_head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* NULL or not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_memcmp(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].ta_curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].ta_head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static struct rsbac_list_item_t *ta_lookup_item(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	if (unlikely(!list || !desc))
		return NULL;

	if (!hashed[hash].ta_copied)
		return lookup_item(list, hashed, hash, desc);
	if (hashed[hash].ta_copied != ta_number)
		return NULL;

	if (list->compare)
		return ta_lookup_item_compare(list, hashed, hash, desc);
	else
		return ta_lookup_item_memcmp(list, hashed, hash, desc);
}

static inline struct rsbac_list_item_t *ta_lookup_item_compare_locked(
	struct rsbac_list_reg_item_t *list, u_int hash, void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !desc || !list->compare))
		return NULL;

	curr = list->hashed[hash].ta_curr;
	if (!curr) {
		curr = list->hashed[hash].ta_head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].ta_curr, curr);
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* NULL or not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static inline struct rsbac_list_item_t *ta_lookup_item_memcmp_locked(
	struct rsbac_list_reg_item_t *list, u_int hash,	void *desc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !desc))
		return NULL;

	curr = list->hashed[hash].ta_curr;
	if (!curr) {
		curr = list->hashed[hash].ta_head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].ta_curr, curr);
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_item_t *ta_lookup_item_locked(const rsbac_list_ta_number_t ta_number,
						struct
						rsbac_list_reg_item_t
						*list, u_int hash, void *desc)
{
	if (unlikely(!list || !desc))
		return NULL;

	if (!list->hashed[hash].ta_copied)
		return lookup_item_locked(list, hash, desc);
	if (list->hashed[hash].ta_copied != ta_number)
		return NULL;

	if (list->compare)
		return ta_lookup_item_compare_locked(list, hash, desc);
	else
		return ta_lookup_item_memcmp_locked(list, hash, desc);
}
#endif

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_data_compare(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && (   (curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_data_memcmp(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_item_t *lookup_item_data(
	struct rsbac_list_reg_item_t * list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if (compare)
		return lookup_item_data_compare(list, hashed, hash_bits, data, compare);
	else
		return lookup_item_data_memcmp(list, hashed, hash_bits, data);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_data_compare(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_reg_item_t * list,
		struct rsbac_list_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && (   (curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_data_memcmp(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_reg_item_t *list,
		struct rsbac_list_hashed_t * hashed,
		const __u8 hash_bits,
		void *data)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && (   (curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_item_t *ta_lookup_item_data(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_reg_item_t *list,
		struct rsbac_list_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if(!ta_number)
		return lookup_item_data(list, hashed, hash_bits, data, compare);
	if (compare)
		return ta_lookup_item_data_compare(ta_number, list, hashed, hash_bits, data, compare);
	else
		return ta_lookup_item_data_memcmp(ta_number, list, hashed, hash_bits, data);
}
#endif

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_data_compare_selector(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_item_data_memcmp_selector(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_item_t *lookup_item_data_selector(
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if (compare)
		return lookup_item_data_compare_selector(list,
						hashed, hash_bits,
						data, compare,
						selector,
						param);
	else
		return lookup_item_data_memcmp_selector(list,
						hashed, hash_bits,
						data,
						selector,
						param);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_data_compare_selector(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *ta_lookup_item_data_memcmp_selector(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_item_t *ta_lookup_item_data_selector(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_reg_item_t *list,
	struct rsbac_list_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if(!ta_number)
		return lookup_item_data_selector(
			list, hashed, hash_bits,
			data, compare,
			selector, param);
	if (compare)
		return ta_lookup_item_data_compare_selector(
			ta_number, list,
			hashed, hash_bits,
			data, compare,
			selector, param);
	else
		return ta_lookup_item_data_memcmp_selector(
			ta_number, list,
			hashed, hash_bits,
			data,
			selector, param);
}
#endif

/* list of lists - subitems */

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_lol_subitem_compare(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_item_t *sublist,
	void *subdesc,
	rsbac_list_compare_function_t compare)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !sublist || !subdesc || !compare))
		return NULL;

	curr = rcu_dereference(sublist->curr);
	if (!curr) {
		curr = rcu_dereference(sublist->head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = compare(&curr[1], subdesc);
	if (compres) {
		if (compres < 0) {
			curr = rcu_dereference(curr->next);
			while (curr && (compare(&curr[1], subdesc) < 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr && (compare(&curr[1], subdesc) > 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!compare(&curr[1], subdesc))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_lol_subitem_memcmp(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_item_t *sublist,
	void *subdesc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !sublist || !subdesc))
		return NULL;

	curr = rcu_dereference(sublist->curr);
	if (!curr) {
		curr = rcu_dereference(sublist->head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(subdesc, &curr[1], list->info.subdesc_size);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr
			       && (memcmp(subdesc,
					  &curr[1],
					  list->info.subdesc_size) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr
			       && (memcmp(subdesc,
					  &curr[1],
					  list->info.subdesc_size) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!memcmp(subdesc,
				    &curr[1], list->info.subdesc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static struct rsbac_list_item_t *lookup_lol_subitem(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_item_t *sublist,
	void *subdesc)
{
	if (unlikely(!list || !sublist || !subdesc))
		return NULL;

	if (list->subcompare)
		return lookup_lol_subitem_compare(list, sublist, subdesc,
						  list->subcompare);
	else
		return lookup_lol_subitem_memcmp(list, sublist, subdesc);
}

static inline struct rsbac_list_item_t *lookup_lol_subitem_compare_locked(struct
							    rsbac_list_lol_reg_item_t
							    *list,
							    struct
							    rsbac_list_lol_item_t
							    *sublist,
							    void *subdesc,
							    rsbac_list_compare_function_t
							    compare)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !sublist || !subdesc || !compare))
		return NULL;

	curr = sublist->curr;
	if (!curr) {
		curr = sublist->head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = compare(&curr[1], subdesc);
	if (compres) {
		if (compres < 0) {
			curr = curr->next;
			while (curr && (compare(&curr[1], subdesc) < 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr && (compare(&curr[1], subdesc) > 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(sublist->curr, curr);
			if (!compare(&curr[1], subdesc))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static inline struct rsbac_list_item_t *lookup_lol_subitem_memcmp_locked(struct
							   rsbac_list_lol_reg_item_t
							   *list,
							   struct
							   rsbac_list_lol_item_t
							   *sublist,
							   void *subdesc)
{
	struct rsbac_list_item_t *curr;
	int compres;

	if (unlikely(!list || !sublist || !subdesc))
		return NULL;

	curr = sublist->curr;
	if (!curr) {
		curr = sublist->head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(subdesc, &curr[1], list->info.subdesc_size);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr
			       && (memcmp(subdesc,
					  &curr[1],
					  list->info.subdesc_size) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr
			       && (memcmp(subdesc,
					  &curr[1],
					  list->info.subdesc_size) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(sublist->curr, curr);
			if (!memcmp(subdesc,
				    &curr[1], list->info.subdesc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_item_t *lookup_lol_subitem_locked(struct
						    rsbac_list_lol_reg_item_t
						    *list,
						    struct
						    rsbac_list_lol_item_t
						    *sublist,
						    void *subdesc)
{
	if (unlikely(!list || !sublist || !subdesc))
		return NULL;

	if (list->subcompare)
		return lookup_lol_subitem_compare_locked(list, sublist, subdesc,
						  list->subcompare);
	else
		return lookup_lol_subitem_memcmp_locked(list, sublist, subdesc);
}

/* Call RCU locked */
static inline struct rsbac_list_item_t *lookup_lol_subitem_user_compare(struct
								 rsbac_list_lol_reg_item_t
								 *list,
								 struct
								 rsbac_list_lol_item_t
								 *sublist,
								 void
								 *subdesc,
								 rsbac_list_compare_function_t
								 compare)
{
	struct rsbac_list_item_t *curr;

	if (unlikely(!list || !sublist || !subdesc || !compare))
		return NULL;

	curr = rcu_dereference(sublist->head);
	/* note: item desc is behind official struct */
	while (curr) {
		if (!compare(&curr[1], subdesc))
			return curr;
		curr = rcu_dereference(curr->next);
	}
	return curr;
}

/* list of lists - items */

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_compare(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_memcmp(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t *lookup_lol_item(
	struct rsbac_list_lol_reg_item_t * list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	if (unlikely(!list || !desc || !hashed))
		return NULL;

	if (list->compare)
		return lookup_lol_item_compare(list, hashed, hash, desc);
	else
		return lookup_lol_item_memcmp(list, hashed, hash, desc);
}

static inline struct rsbac_list_lol_item_t *lookup_lol_item_compare_locked(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	if (unlikely(!list || !desc || !list->compare))
		return NULL;

	curr = list->hashed[hash].curr;
	if (!curr) {
		curr = list->hashed[hash].head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].curr, curr);
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static inline struct rsbac_list_lol_item_t *lookup_lol_item_memcmp_locked(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	if (unlikely(!list || !desc))
		return NULL;

	curr = list->hashed[hash].curr;
	if (!curr) {
		curr = list->hashed[hash].head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].curr, curr);
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_lol_item_t *lookup_lol_item_locked(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc)
{
	if (unlikely(!list || !desc))
		return NULL;

	if (list->compare)
		return lookup_lol_item_compare_locked(list, hash, desc);
	else
		return lookup_lol_item_memcmp_locked(list, hash, desc);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_compare(
	struct rsbac_list_lol_reg_item_t * list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].ta_curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].ta_head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_memcmp(
	struct rsbac_list_lol_reg_item_t * list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	curr = rcu_dereference(hashed[hash].ta_curr);
	if (!curr) {
		curr = rcu_dereference(hashed[hash].ta_head);
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = rcu_dereference(curr->next);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = rcu_dereference(curr->next);
		} else {
			curr = rcu_dereference(curr->prev);
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = rcu_dereference(curr->prev);
		}
		if (curr) {
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t *ta_lookup_lol_item(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	u_int hash,
	void *desc)
{
	if (unlikely(!list || !desc || !hashed))
		return NULL;

	if (!hashed[hash].ta_copied)
		return lookup_lol_item(list, hashed, hash, desc);
	if (hashed[hash].ta_copied != ta_number)
		return NULL;

	if (list->compare)
		return ta_lookup_lol_item_compare(list, hashed, hash, desc);
	else
		return ta_lookup_lol_item_memcmp(list, hashed, hash, desc);
}

static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_compare_locked(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	if (unlikely(!list || !desc || !list->compare))
		return NULL;

	curr = list->hashed[hash].ta_curr;
	if (!curr) {
		curr = list->hashed[hash].ta_head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = list->compare(desc, &curr[1]);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr && (list->compare(desc, &curr[1]) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr && (list->compare(desc, &curr[1]) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].ta_curr, curr);
			if (!list->compare(desc, &curr[1]))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_memcmp_locked(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc)
{
	struct rsbac_list_lol_item_t *curr;
	int compres;

	if (unlikely(!list || !desc))
		return NULL;

	curr = list->hashed[hash].ta_curr;
	if (!curr) {
		curr = list->hashed[hash].ta_head;
		if (!curr)
			return NULL;
	}
	/* if current item is not the right one, search... */
	/* note: item desc is behind official struct */
	compres = memcmp(desc, &curr[1], list->info.desc_size);
	if (compres) {
		if (compres > 0) {
			curr = curr->next;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) > 0)
			    )
				curr = curr->next;
		} else {
			curr = curr->prev;
			while (curr
			       && (memcmp(desc,
					  &curr[1],
					  list->info.desc_size) < 0)
			    )
				curr = curr->prev;
		}
		if (curr) {
			rcu_assign_pointer(list->hashed[hash].ta_curr, curr);
			if (!memcmp(desc, &curr[1], list->info.desc_size))
				return curr;
		}
		/* not found */
		return NULL;
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_lol_item_t
    *ta_lookup_lol_item_locked(const rsbac_list_ta_number_t ta_number,
			struct rsbac_list_lol_reg_item_t *list, u_int hash, void *desc)
{
	if (unlikely(!list || !desc))
		return NULL;

	if (!list->hashed[hash].ta_copied)
		return lookup_lol_item_locked(list, hash, desc);
	if (list->hashed[hash].ta_copied != ta_number)
		return NULL;

	if (list->compare)
		return ta_lookup_lol_item_compare_locked(list, hash, desc);
	else
		return ta_lookup_lol_item_memcmp_locked(list, hash, desc);
}
#endif

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_data_compare(
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_data_memcmp(
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t *lookup_lol_item_data(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if (compare)
		return lookup_lol_item_data_compare(list, hashed, hash_bits, data, compare);
	else
		return lookup_lol_item_data_memcmp(list, hashed, hash_bits, data);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_data_compare(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_data_memcmp(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t *ta_lookup_lol_item_data(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t compare)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if(!ta_number)
		return lookup_lol_item_data(list, hashed, hash_bits, data, compare);
	if (compare)
		return ta_lookup_lol_item_data_compare(ta_number, list,
							hashed, hash_bits,
							data,
							compare);
	else
		return ta_lookup_lol_item_data_memcmp(ta_number, list,
							hashed, hash_bits,
							data);
}
#endif

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_data_compare_selector(
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *lookup_lol_item_data_memcmp_selector(
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	if (unlikely(!list || !data))
		return NULL;

	for(i=0; i<nr_hashes; i++) {
		curr = rcu_dereference(hashed[i].head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t *lookup_lol_item_data_selector(
	struct rsbac_list_lol_reg_item_t *list,
	struct rsbac_list_lol_hashed_t * hashed,
	const __u8 hash_bits,
	void *data,
	rsbac_list_data_compare_function_t
	compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if (compare)
		return lookup_lol_item_data_compare_selector(list, hashed, hash_bits, data, compare, selector, param);
	else
		return lookup_lol_item_data_memcmp_selector(list, hashed, hash_bits, data, selector, param);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_data_compare_selector(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || compare((char *) curr + sizeof(*curr) +
				      list->info.desc_size, data)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static inline struct rsbac_list_lol_item_t *ta_lookup_lol_item_data_memcmp_selector(
		const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_lol_item_t *curr;
	int i;
	const u_int nr_hashes = BIT(hash_bits);

	for(i=0; i<nr_hashes; i++) {
		if (!hashed[i].ta_copied || hashed[i].ta_copied != ta_number)
			curr = rcu_dereference(hashed[i].head);
		else
			curr = rcu_dereference(hashed[i].ta_head);

		/* note: item desc is behind official struct */
		while (curr
		       && ((curr->max_age && (curr->max_age <= RSBAC_CURRENT_TIME))
			   || memcmp(data,
				     &curr[1] + list->info.desc_size,
				     list->info.data_size)
			   || !selector((char *) curr + sizeof(*curr), param)
		       )
		    )
			curr = rcu_dereference(curr->next);
		if(curr)
			return curr;
	}
	return NULL;
}

/* Call RCU locked */
static struct rsbac_list_lol_item_t
    *ta_lookup_lol_item_data_selector(const rsbac_list_ta_number_t ta_number,
		struct rsbac_list_lol_reg_item_t *list,
		struct rsbac_list_lol_hashed_t * hashed,
		const __u8 hash_bits,
		void *data,
		rsbac_list_data_compare_function_t compare,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	if (unlikely(!list || !data || !hashed))
		return NULL;

	if(likely(!ta_number))
		return lookup_lol_item_data_selector(list, hashed, hash_bits, data, compare,
				selector, param);
	if (compare)
		return ta_lookup_lol_item_data_compare_selector(ta_number, list,
				hashed, hash_bits, data,
				compare, selector, param);
	else
		return ta_lookup_lol_item_data_memcmp_selector(ta_number,
				list, hashed, hash_bits,
				data, selector, param);
}
#endif

/* Registration lookup */

static struct rsbac_list_reg_item_t *lookup_reg(struct rsbac_list_reg_item_t *handle)
{
	struct rsbac_list_reg_item_t *curr = srcu_dereference(reg_head.curr, &reg_list_srcu);

	if (unlikely(!handle))
		return NULL;
	/* if there is no current item or it is not the right one, search... */
	if (curr != handle) {
		curr = srcu_dereference(reg_head.head, &reg_list_srcu);
		while (curr && curr != handle)
			curr = srcu_dereference(curr->next, &reg_list_srcu);
		if (!curr)
			rsbac_pr_debug(lists,
				       "Lookup of unknown list handle %p\n",
				       handle);
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_reg_item_t *lookup_reg_name(char *name, __u32 major, __u32 minor)
{
	struct rsbac_list_reg_item_t *curr = srcu_dereference(reg_head.curr, &reg_list_srcu);

	if (unlikely(!name))
		return NULL;
	/* if there is no current item or it is not the right one, search... */
	if (!curr || (strncmp(curr->name, name, RSBAC_LIST_MAX_FILENAME)
		  || (curr->minor != minor)
		  || (curr->major != major)
	    )
	    ) {
		curr = srcu_dereference(reg_head.head, &reg_list_srcu);
		while (curr &&
		       (   strncmp(curr->name, name, RSBAC_LIST_MAX_FILENAME)
			|| (curr->minor != minor)
			|| (curr->major != major)
		       )
		    )
			curr = srcu_dereference(curr->next, &reg_list_srcu);
		if (!curr)
			rsbac_pr_debug(lists, "Lookup of unknown list name %s "
				       "on device %02u:%02u\n", name,
				       major, minor);
	}
	/* it is the current item -> return it */
	return curr;
}

/* List of lists registration lookup */

static struct rsbac_list_lol_reg_item_t *lookup_lol_reg(struct
							rsbac_list_lol_reg_item_t
							*handle)
{
	struct rsbac_list_lol_reg_item_t *curr = srcu_dereference(lol_reg_head.curr, &lol_reg_list_srcu);

	if (unlikely(!handle))
		return NULL;
	/* if there is no current item or it is not the right one, search... */
	if (curr != handle) {
		curr = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
		while (curr && curr != handle)
			curr = srcu_dereference(curr->next, &lol_reg_list_srcu);
		if (!curr)
			rsbac_pr_debug(lists, "Lookup of unknown list handle %p\n",
				     handle);
	}
	/* it is the current item -> return it */
	return curr;
}

static struct rsbac_list_lol_reg_item_t *lookup_lol_reg_name(char *name,
							     __u32 major, __u32 minor)
{
	struct rsbac_list_lol_reg_item_t *curr = srcu_dereference(lol_reg_head.curr, &lol_reg_list_srcu);

	if (unlikely(!name))
		return NULL;
	/* if there is no current item or it is not the right one, search... */
	if (!curr || (strncmp(curr->name, name, RSBAC_LIST_MAX_FILENAME)
			|| (curr->minor != minor)
			|| (curr->major != major)
	    )
	    ) {
		curr = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
		while (curr
		       &&
		       (   strncmp(curr->name, name, RSBAC_LIST_MAX_FILENAME)
			|| (curr->minor != minor)
			|| (curr->major != major)
		       )
		    )
			curr = srcu_dereference(curr->next, &lol_reg_list_srcu);
		if (!curr)
			rsbac_pr_debug(lists, "Lookup of unknown list name %s "
				       "on device %02u:%02u\n", name,
				       major, minor);
	}
	/* it is the current item -> return it */
	return curr;
}

/*************/
/* Add items */

/* Call spinlocked */
static inline struct rsbac_list_item_t *insert_item_compare(
	struct rsbac_list_reg_item_t * list,
	u_int hash,
	void *desc,
	struct rsbac_list_item_t * new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = list->hashed[hash].curr;
	if (!curr)
		curr = list->hashed[hash].head;
	if ((list->compare(desc, &curr[1]) > 0)) {
		curr = curr->next;
		while (curr && (list->compare(desc, &curr[1]) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr && (list->compare(desc, &curr[1]) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].head;
			rcu_assign_pointer(list->hashed[hash].head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		}
	}
	list->hashed[hash].count++;
	rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static inline struct rsbac_list_item_t *insert_item_memcmp(
	struct rsbac_list_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_item_t *new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = list->hashed[hash].curr;
	if (!curr)
		curr = list->hashed[hash].head;
	if (memcmp(desc, &curr[1], list->info.desc_size) > 0) {
		curr = curr->next;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].head;
			rcu_assign_pointer(list->hashed[hash].head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		}
	}
	list->hashed[hash].count++;
	rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static struct rsbac_list_item_t *add_item(struct rsbac_list_reg_item_t *list,
					  u_int hash,
					  rsbac_time_t max_age,
					  void *desc, void *data)
{
	struct rsbac_list_item_t *new_item_p = NULL;

	if (unlikely(!list || !desc))
		return NULL;
	if (unlikely(list->info.data_size && !data))
		return NULL;

	/* item desc and data are behind official struct */
	if (list->slab)
		new_item_p = rsbac_smalloc(list->slab);
	else
		new_item_p = rsbac_kmalloc(sizeof(*new_item_p)
						+ list->info.desc_size
						+ list->info.data_size);
	if (unlikely(!new_item_p))
		return NULL;

	new_item_p->max_age = max_age;
	/* item desc is behind official struct */
	memcpy(&new_item_p[1], desc, list->info.desc_size);
	/* item data is behind official struct and desc */
	/* data might be empty! */
	if (data && list->info.data_size)
		memcpy(((__u8 *) new_item_p) + sizeof(*new_item_p) +
		       list->info.desc_size, data, list->info.data_size);

	if (!list->hashed[hash].head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
		list->hashed[hash].count = 1;
		return new_item_p;
	}
	if(list->hashed[hash].count >= list->max_items_per_hash) {
		rsbac_sfree(list->slab, new_item_p);
		if (!(list->flags & RSBAC_LIST_NO_MAX_WARN))
			rsbac_printk(KERN_WARNING "add_item(): cannot add item to list %s, hash %u on device %02u:%02u, would be more than %u items!\n",
			     list->name,
			     hash,
			     list->major, list->minor,
			     list->max_items_per_hash);
	  	return NULL;
	}
	if (list->compare)
		return insert_item_compare(list, hash, desc, new_item_p);
	else
		return insert_item_memcmp(list, hash, desc, new_item_p);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
static void ta_remove_all_items(struct rsbac_list_reg_item_t *list, u_int hash);

/* Call spinlocked */
static int ta_copy(const rsbac_list_ta_number_t ta_number,
		   struct rsbac_list_reg_item_t *list,
		   u_int hash)
{
	struct rsbac_list_item_t *curr;
	struct rsbac_list_item_t *new_item_p;
	u_int item_size = sizeof(*new_item_p)
	    + list->info.desc_size + list->info.data_size;

	/* write access to ta_* is safe for readers as long as ta_copied is not set */
	curr = list->hashed[hash].head;
	if (curr) {
		if (list->slab)
			new_item_p = rsbac_smalloc(list->slab);
		else
			new_item_p = rsbac_kmalloc(item_size);
		if (!new_item_p) {
			ta_remove_all_items(list, hash);
			return -RSBAC_ENOMEM;
		}
		memcpy(new_item_p, curr, item_size);
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		list->hashed[hash].ta_head = new_item_p;
		list->hashed[hash].ta_tail = new_item_p;
		list->hashed[hash].ta_curr = new_item_p;
		list->hashed[hash].ta_count = 1;
		curr = curr->next;
	} else {
		list->hashed[hash].ta_head = NULL;
		list->hashed[hash].ta_tail = NULL;
		list->hashed[hash].ta_curr = NULL;
		list->hashed[hash].ta_count = 0;
		list->hashed[hash].ta_copied = ta_number;
		return 0;
	}
	while (curr) {
		if (list->slab)
			new_item_p = rsbac_smalloc(list->slab);
		else
			new_item_p = rsbac_kmalloc(item_size);
		if (!new_item_p) {
			ta_remove_all_items(list, hash);
			return -RSBAC_ENOMEM;
		}
		memcpy(new_item_p, curr, item_size);
		new_item_p->prev = list->hashed[hash].ta_tail;
		new_item_p->next = NULL;
		list->hashed[hash].ta_tail->next = new_item_p;
		list->hashed[hash].ta_tail = new_item_p;
		list->hashed[hash].ta_count++;
		curr = curr->next;
	}
	list->hashed[hash].ta_copied = ta_number;
	return 0;
}

static void ta_remove_all_lol_items(struct rsbac_list_lol_reg_item_t *list,
				u_int hash);

/* Call spinlocked */
static int ta_lol_copy(const rsbac_list_ta_number_t ta_number,
		       struct rsbac_list_lol_reg_item_t *list,
		       u_int hash)
{
	struct rsbac_list_lol_item_t *curr;
	struct rsbac_list_lol_item_t *new_item_p;
	struct rsbac_list_item_t *sub_curr;
	struct rsbac_list_item_t *new_subitem_p;
	u_int item_size = sizeof(*new_item_p)
	    + list->info.desc_size + list->info.data_size;
	u_int subitem_size = sizeof(*new_subitem_p)
	    + list->info.subdesc_size + list->info.subdata_size;

	/* write access to ta_* is safe for readers as long as ta_copied is not set */
	list->hashed[hash].ta_head = NULL;
	list->hashed[hash].ta_tail = NULL;
	list->hashed[hash].ta_curr = NULL;
	list->hashed[hash].ta_count = 0;

	curr = list->hashed[hash].head;
	while (curr) {
		if (list->slab)
			new_item_p = rsbac_smalloc(list->slab);
		else
			new_item_p = rsbac_kmalloc(item_size);
		if (!new_item_p) {
			ta_remove_all_lol_items(list, hash);
			return -RSBAC_ENOMEM;
		}
		memcpy(new_item_p, curr, item_size);
		new_item_p->head = NULL;
		new_item_p->tail = NULL;
		new_item_p->curr = NULL;
		new_item_p->count = 0;
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		sub_curr = curr->head;
		while (sub_curr) {
			if (list->subslab)
				new_subitem_p = rsbac_smalloc(list->subslab);
			else
				new_subitem_p = rsbac_kmalloc(subitem_size);
			if (!new_subitem_p) {
				ta_remove_all_lol_items(list, hash);
				rsbac_sfree(list->slab, new_item_p);
				return -RSBAC_ENOMEM;
			}
			memcpy(new_subitem_p, sub_curr, subitem_size);
			new_subitem_p->prev = NULL;
			new_subitem_p->next = NULL;
			if (new_item_p->tail) {
				new_subitem_p->prev = new_item_p->tail;
				new_item_p->tail->next = new_subitem_p;
				new_item_p->tail = new_subitem_p;
				new_item_p->count++;
			} else {
				new_item_p->head = new_subitem_p;
				new_item_p->tail = new_subitem_p;
				new_item_p->count = 1;
			}
			sub_curr = sub_curr->next;
		}
		if (list->hashed[hash].ta_tail) {
			new_item_p->prev = list->hashed[hash].ta_tail;
			list->hashed[hash].ta_tail->next = new_item_p;
			list->hashed[hash].ta_tail= new_item_p;
			list->hashed[hash].ta_count++;
		} else {
			list->hashed[hash].ta_head = new_item_p;
			list->hashed[hash].ta_tail = new_item_p;
			list->hashed[hash].ta_curr = new_item_p;
			list->hashed[hash].ta_count = 1;
		}
		curr = curr->next;
	}
	list->hashed[hash].ta_copied = ta_number;
	return 0;
}

/* Call spinlocked */
static inline struct rsbac_list_item_t *ta_insert_item_compare(
	struct rsbac_list_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_item_t *new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = list->hashed[hash].ta_curr;
	if (!curr)
		curr = list->hashed[hash].ta_head;
	if ((list->compare(desc, &curr[1]) > 0)) {
		curr = curr->next;
		while (curr && (list->compare(desc, &curr[1]) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].ta_tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].ta_tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr && (list->compare(desc, &curr[1]) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].ta_head;
			rcu_assign_pointer(list->hashed[hash].ta_head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		}
	}
	list->hashed[hash].ta_count++;
	rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static inline struct rsbac_list_item_t *ta_insert_item_memcmp(
	struct rsbac_list_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_item_t *new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = list->hashed[hash].ta_curr;
	if (!curr)
		curr = list->hashed[hash].ta_head;
	if (memcmp(desc, &curr[1], list->info.desc_size) > 0) {
		curr = curr->next;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].ta_tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].ta_tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].ta_head;
			rcu_assign_pointer(list->hashed[hash].ta_head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		}
	}
	list->hashed[hash].ta_count++;
	rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static struct rsbac_list_item_t *ta_add_item(const rsbac_list_ta_number_t ta_number,
					     struct rsbac_list_reg_item_t *list,
					     u_int hash,
					     rsbac_time_t max_age,
					     void *desc, void *data)
{
	struct rsbac_list_item_t *new_item_p = NULL;

	if (unlikely(!list || !desc))
		return NULL;
	if (unlikely(list->info.data_size && !data))
		return NULL;
	if (!ta_number)
		return add_item(list, hash, max_age, desc, data);
	/* item desc and data are behind official struct */
	if (list->slab)
		new_item_p = rsbac_smalloc(list->slab);
	else
		new_item_p = rsbac_kmalloc(sizeof(*new_item_p)
						+ list->info.desc_size
						+ list->info.data_size);
	if (unlikely(!new_item_p))
		return NULL;
	new_item_p->max_age = max_age;
	/* item desc is behind official struct */
	memcpy(&new_item_p[1], desc, list->info.desc_size);
	/* item data is behind official struct and desc */
	/* data might be empty! */
	if (data && list->info.data_size)
		memcpy(((__u8 *) new_item_p) + sizeof(*new_item_p) +
		       list->info.desc_size, data, list->info.data_size);

	if (!list->hashed[hash].ta_copied) {	/* copy list to ta_list */
		if (ta_copy(ta_number, list, hash)) {
			rsbac_sfree(list->slab, new_item_p);
			return NULL;
		}
	} else {
		if (list->hashed[hash].ta_copied != ta_number) {
			rsbac_sfree(list->slab, new_item_p);
			return NULL;
		}
	}

	if (!list->hashed[hash].ta_head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
		list->hashed[hash].ta_count = 1;
		return new_item_p;
	}
	if (list->hashed[hash].ta_count >= list->max_items_per_hash) {
		rsbac_sfree(list->slab, new_item_p);
		if (!(list->flags & RSBAC_LIST_NO_MAX_WARN))
			rsbac_printk(KERN_WARNING "ta_add_item(): cannot add item to list %s, hash %u on device %02u:%02u, would be more than %u items!\n",
			     list->name,
			     hash,
			     list->major, list->minor,
			     list->max_items_per_hash);
	  	return NULL;
	}
	if (list->compare)
		return ta_insert_item_compare(list, hash, desc, new_item_p);
	else
		return ta_insert_item_memcmp(list, hash, desc, new_item_p);
}
#endif


/* Call spinlocked */
static inline struct rsbac_list_item_t *insert_lol_subitem_compare(struct
							    rsbac_list_lol_reg_item_t
							    *list,
							    struct
							    rsbac_list_lol_item_t
							    *sublist,
							    void *subdesc,
							    struct
							    rsbac_list_item_t
							    *new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = sublist->curr;
	if (!curr)
		curr = sublist->head;
	if ((list->subcompare(subdesc, &curr[1]) > 0)) {
		curr = curr->next;
		while (curr && (list->subcompare(subdesc, &curr[1]) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = sublist->tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(sublist->tail->next, new_item_p);
			rcu_assign_pointer(sublist->tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr && (list->subcompare(subdesc, &curr[1]) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = sublist->head;
			rcu_assign_pointer(sublist->head->prev, new_item_p);
			rcu_assign_pointer(sublist->head, new_item_p);
		}
	}
	sublist->count++;
	rcu_assign_pointer(sublist->curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static inline struct rsbac_list_item_t *insert_lol_subitem_memcmp(struct
							   rsbac_list_lol_reg_item_t
							   *list,
							   struct
							   rsbac_list_lol_item_t
							   *sublist,
							   void *subdesc,
							   struct
							   rsbac_list_item_t
							   *new_item_p)
{
	struct rsbac_list_item_t *curr;

	curr = sublist->curr;
	if (!curr)
		curr = sublist->head;
	if (memcmp(subdesc, &curr[1], list->info.subdesc_size) > 0) {
		curr = curr->next;
		while (curr
		       && (memcmp(subdesc,
				  &curr[1], list->info.subdesc_size) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = sublist->tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(sublist->tail->next, new_item_p);
			rcu_assign_pointer(sublist->tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr
		       && (memcmp(subdesc,
				  &curr[1], list->info.subdesc_size) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = sublist->head;
			rcu_assign_pointer(sublist->head->prev, new_item_p);
			rcu_assign_pointer(sublist->head, new_item_p);
		}
	}
	sublist->count++;
	rcu_assign_pointer(sublist->curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static struct rsbac_list_item_t *add_lol_subitem(struct
						 rsbac_list_lol_reg_item_t
						 *list,
						 struct
						 rsbac_list_lol_item_t
						 *sublist,
						 rsbac_time_t max_age,
						 void *subdesc,
						 void *subdata)
{
	struct rsbac_list_item_t *new_item_p = NULL;

	if (unlikely(!list || !sublist || !subdesc))
		return NULL;
	if (unlikely(list->info.subdata_size && !subdata))
		return NULL;
	/* item desc and data are behind official struct */
	if (list->subslab)
		new_item_p = rsbac_smalloc(list->subslab);
	else
		new_item_p = rsbac_kmalloc(sizeof(*new_item_p)
						+ list->info.subdesc_size
						+ list->info.subdata_size);
	if (unlikely(!new_item_p))
		return NULL;

	new_item_p->max_age = max_age;
	/* item desc is behind official struct */
	memcpy(&new_item_p[1], subdesc, list->info.subdesc_size);
	/* item data is behind official struct and desc */
	/* subdata might be empty! */
	if (subdata && list->info.subdata_size)
		memcpy(((__u8 *) new_item_p) + sizeof(*new_item_p) +
		       list->info.subdesc_size, subdata,
		       list->info.subdata_size);

	/* Sublist was empty */
	if (!sublist->head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(sublist->head, new_item_p);
		rcu_assign_pointer(sublist->tail, new_item_p);
		rcu_assign_pointer(sublist->curr, new_item_p);
		sublist->count = 1;
		return new_item_p;
	}
	if (sublist->count >= list->max_subitems) {
		rsbac_sfree(list->slab, new_item_p);
		if (!(list->flags & RSBAC_LIST_NO_MAX_WARN))
			rsbac_printk(KERN_WARNING "add_lol_subitem(): cannot add subitem to sublist of %s on device %02u:%02u, would be more than %u subitems!\n",
			     list->name,
			     list->major, list->minor,
			     list->max_subitems);
	  	return NULL;
	}
	if (list->subcompare)
		return insert_lol_subitem_compare(list, sublist, subdesc,
						  new_item_p);
	else
		return insert_lol_subitem_memcmp(list, sublist, subdesc,
						 new_item_p);
}

/* Call spinlocked */
static inline struct rsbac_list_lol_item_t *insert_lol_item_compare(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_lol_item_t *new_item_p)
{
	struct rsbac_list_lol_item_t *curr;

	curr = list->hashed[hash].curr;
	if (!curr)
		curr = list->hashed[hash].head;
	if ((list->compare(desc, &curr[1]) > 0)) {
		curr = curr->next;
		while (curr && (list->compare(desc, &curr[1]) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr && (list->compare(desc, &curr[1]) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].head;
			rcu_assign_pointer(list->hashed[hash].head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		}
	}
	list->hashed[hash].count++;
	rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static inline struct rsbac_list_lol_item_t *insert_lol_item_memcmp(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_lol_item_t *new_item_p)
{
	struct rsbac_list_lol_item_t *curr;

	curr = list->hashed[hash].curr;
	if (!curr)
		curr = list->hashed[hash].head;
	if (memcmp(desc, &curr[1], list->info.desc_size) > 0) {
		curr = curr->next;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].head;
			rcu_assign_pointer(list->hashed[hash].head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		}
	}
	list->hashed[hash].count++;
	rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static struct rsbac_list_lol_item_t *add_lol_item(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	rsbac_time_t max_age,
	void *desc,
	void *data)
{
	struct rsbac_list_lol_item_t *new_item_p = NULL;

	if (unlikely(!list || !desc))
		return NULL;
	if (unlikely(list->info.data_size && !data))
		return NULL;
	/* item desc and data are behind official struct */
	if (list->slab)
		new_item_p = rsbac_smalloc(list->slab);
	else
		new_item_p = rsbac_kmalloc(sizeof(*new_item_p)
						+ list->info.desc_size
						+ list->info.data_size);
	if (unlikely(!new_item_p))
		return NULL;

	/* Init sublist */
	new_item_p->head = NULL;
	new_item_p->tail = NULL;
	new_item_p->curr = NULL;
	new_item_p->count = 0;
	new_item_p->max_age = max_age;
	/* item desc is behind official struct */
	memcpy(&new_item_p[1], desc, list->info.desc_size);
	/* item data is behind official struct and desc */
	/* data might be empty! */
	if (data && list->info.data_size)
		memcpy(((__u8 *) new_item_p) + sizeof(*new_item_p) +
		       list->info.desc_size, data, list->info.data_size);

	if (!list->hashed[hash].head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(list->hashed[hash].head, new_item_p);
		rcu_assign_pointer(list->hashed[hash].tail, new_item_p);
		rcu_assign_pointer(list->hashed[hash].curr, new_item_p);
		list->hashed[hash].count = 1;
		return new_item_p;
	}
	if (list->hashed[hash].count >= list->max_items_per_hash) {
		rsbac_sfree(list->slab, new_item_p);
		if (!(list->flags & RSBAC_LIST_NO_MAX_WARN))
			rsbac_printk(KERN_WARNING "add_lol_item(): cannot add item to list %s, hash %u on device %02u:%02u, would be more than %u items!\n",
			     list->name,
			     hash,
			     list->major, list->minor,
			     list->max_items_per_hash);
	  	return NULL;
	}
	if (list->compare)
		return insert_lol_item_compare(list, hash, desc, new_item_p);
	else
		return insert_lol_item_memcmp(list, hash, desc, new_item_p);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call spinlocked */
static inline struct rsbac_list_lol_item_t *ta_insert_lol_item_compare(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_lol_item_t *new_item_p)
{
	struct rsbac_list_lol_item_t *curr;

	curr = list->hashed[hash].ta_curr;
	if (!curr)
		curr = list->hashed[hash].ta_head;
	if ((list->compare(desc, &curr[1]) > 0)) {
		curr = curr->next;
		while (curr && (list->compare(desc, &curr[1]) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].ta_tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].ta_tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr && (list->compare(desc, &curr[1]) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].ta_head;
			rcu_assign_pointer(list->hashed[hash].ta_head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		}
	}
	list->hashed[hash].ta_count++;
	rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static inline struct rsbac_list_lol_item_t *ta_insert_lol_item_memcmp(
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	void *desc,
	struct rsbac_list_lol_item_t *new_item_p)
{
	struct rsbac_list_lol_item_t *curr;
	curr = list->hashed[hash].ta_curr;
	if (!curr)
		curr = list->hashed[hash].ta_head;
	if (memcmp(desc, &curr[1], list->info.desc_size) > 0) {
		curr = curr->next;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) > 0)
		    )
			curr = curr->next;
		if (curr) {
			/* insert before curr */
			new_item_p->prev = curr->prev;
			new_item_p->next = curr;
			rcu_assign_pointer(curr->prev->next, new_item_p);
			rcu_assign_pointer(curr->prev, new_item_p);
		} else {
			/* insert as last item */
			new_item_p->prev = list->hashed[hash].ta_tail;
			new_item_p->next = NULL;
			rcu_assign_pointer(list->hashed[hash].ta_tail->next, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		}
	} else {
		curr = curr->prev;
		while (curr
		       && (memcmp(desc,
				  &curr[1], list->info.desc_size) < 0)
		    )
			curr = curr->prev;
		if (curr) {
			/* insert after curr */
			new_item_p->prev = curr;
			new_item_p->next = curr->next;
			rcu_assign_pointer(curr->next->prev, new_item_p);
			rcu_assign_pointer(curr->next, new_item_p);
		} else {
			/* insert as first item */
			new_item_p->prev = NULL;
			new_item_p->next = list->hashed[hash].ta_head;
			rcu_assign_pointer(list->hashed[hash].ta_head->prev, new_item_p);
			rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		}
	}
	list->hashed[hash].ta_count++;
	rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
	return new_item_p;
}

/* Call spinlocked */
static struct rsbac_list_lol_item_t *ta_add_lol_item(
	const rsbac_list_ta_number_t ta_number,
	struct rsbac_list_lol_reg_item_t *list,
	u_int hash,
	rsbac_time_t max_age,
	void *desc,
	void *data)
{
	struct rsbac_list_lol_item_t *new_item_p = NULL;
	if (unlikely(!list || !desc))
		return NULL;
	if (unlikely(list->info.data_size && !data))
		return NULL;
	if (!ta_number)
		return add_lol_item(list, hash, max_age, desc, data);
	/* item desc and data are behind official struct */
	if (list->slab)
		new_item_p = rsbac_smalloc(list->slab);
	else
		new_item_p = rsbac_kmalloc(sizeof(*new_item_p)
						+ list->info.desc_size
						+ list->info.data_size);
	if (unlikely(!new_item_p))
		return NULL;

	/* Init sublist */
	new_item_p->head = NULL;
	new_item_p->tail = NULL;
	new_item_p->curr = NULL;
	new_item_p->count = 0;
	new_item_p->max_age = max_age;
	new_item_p->prev = NULL;
	new_item_p->next = NULL;
	/* item desc is behind official struct */
	memcpy(&new_item_p[1], desc, list->info.desc_size);
	/* item data is behind official struct and desc */
	/* data might be empty! */
	if (data && list->info.data_size)
		memcpy(((__u8 *) new_item_p) + sizeof(*new_item_p) +
		       list->info.desc_size, data, list->info.data_size);

	if (!list->hashed[hash].ta_copied) {	/* copy list to ta_list */
		if (ta_lol_copy(ta_number, list, hash)) {
			rsbac_sfree(list->slab, new_item_p);
			return NULL;
		}
	} else {
		if (list->hashed[hash].ta_copied != ta_number) {
			rsbac_sfree(list->slab, new_item_p);
			return NULL;
		}
	}

	if (!list->hashed[hash].ta_head) {
		rcu_assign_pointer(list->hashed[hash].ta_head, new_item_p);
		rcu_assign_pointer(list->hashed[hash].ta_tail, new_item_p);
		rcu_assign_pointer(list->hashed[hash].ta_curr, new_item_p);
		list->hashed[hash].ta_count = 1;
		return (new_item_p);
	}
	if (list->hashed[hash].ta_count >= list->max_items_per_hash) {
		rsbac_sfree(list->slab, new_item_p);
		if (!(list->flags & RSBAC_LIST_NO_MAX_WARN))
			rsbac_printk(KERN_WARNING "ta_add_lol_item(): cannot add item to list %s, hash %u on device %02u:%02u, would be more than %u items!\n",
			     list->name,
			     hash,
			     list->major, list->minor,
			     list->max_items_per_hash);
	  	return NULL;
	}
	if (list->compare)
		return ta_insert_lol_item_compare(list, hash, desc, new_item_p);
	else
		return ta_insert_lol_item_memcmp(list, hash, desc, new_item_p);
}
#endif

/* Add registration items */

/* no locking needed */
static inline struct rsbac_list_reg_item_t *create_reg(
		struct rsbac_list_info_t *info_p,
		u_int flags,
		rsbac_list_compare_function_t * compare,
		rsbac_list_get_conv_t * get_conv,
		void *def_data,
		char *name,
		__u32 major, __u32 minor,
		const __u8 hash_bits,
		rsbac_list_hash_function_t hash_function,
		char * old_name_base)
{
	struct rsbac_list_reg_item_t *new_item_p = NULL;
	const u_int nr_hashes = BIT(hash_bits);
	int i;

	if (!(new_item_p = rsbac_smalloc_clear_unlocked(reg_item_slab)))
		return NULL;
	if (!(new_item_p->hashed = rsbac_kmalloc_clear_unlocked(nr_hashes*sizeof(struct rsbac_list_hashed_t)))) {
		rsbac_sfree(reg_item_slab, new_item_p);
		return NULL;
	}
	for (i=0; i<nr_hashes; i++) {
		spin_lock_init(&new_item_p->hashed[i].lock);
		lockdep_set_class(&new_item_p->hashed[i].lock, &list_lock_class);
	}
	new_item_p->info = *info_p;
	if (!def_data)
		flags &= ~RSBAC_LIST_DEF_DATA;
	new_item_p->flags = flags;
	new_item_p->compare = compare;
	new_item_p->get_conv = get_conv;
	if (flags & RSBAC_LIST_DEF_DATA) {
		new_item_p->def_data = rsbac_kmalloc_unlocked(info_p->data_size);
		if (new_item_p->def_data)
			memcpy(new_item_p->def_data, def_data,
			       info_p->data_size);
		else {
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(reg_item_slab, new_item_p);
			return NULL;
		}
	} else
		new_item_p->def_data = NULL;
	if (name) {
		strncpy(new_item_p->name, name, RSBAC_LIST_MAX_FILENAME);
		new_item_p->name[RSBAC_LIST_MAX_FILENAME] = 0;
	} else {
		strcpy(new_item_p->name, RSBAC_LIST_NONAME);
	}
	new_item_p->hash_bits = hash_bits;
	if (flags & RSBAC_LIST_NO_MAX)
		new_item_p->max_items_per_hash = RSBAC_LIST_MAX_NR_ITEMS_LIMIT;
	else
		new_item_p->max_items_per_hash = RSBAC_LIST_MAX_NR_ITEMS;
	new_item_p->hash_function = hash_function;
	if (old_name_base) {
		strncpy(new_item_p->old_name_base, old_name_base, RSBAC_LIST_MAX_FILENAME);
		new_item_p->old_name_base[RSBAC_LIST_MAX_FILENAME] = 0;
	} else {
		new_item_p->old_name_base[0] = 0;
	}
	new_item_p->major = major;
	new_item_p->minor = minor;
	rwlock_init(&new_item_p->hash_lock);
	if (flags & RSBAC_LIST_OWN_SLAB) {
		new_item_p->slabname = rsbac_kmalloc(RSBAC_MAX_SLABNAME);
		if (!new_item_p->slabname) {
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(reg_item_slab, new_item_p);
			if (new_item_p->def_data)
				rsbac_kfree(new_item_p->def_data);
			return NULL;
		}
		if (!RSBAC_IS_AUTO_DEV(major, minor)) {
			snprintf(new_item_p->slabname,
				RSBAC_MAX_SLABNAME,
				"%s-%02u:%02u",
				name,
				major, minor);
		} else {
			strncpy(new_item_p->slabname, name, RSBAC_MAX_SLABNAME);
		}
		new_item_p->slabname[RSBAC_MAX_SLABNAME - 1] = 0;
		new_item_p->slab = rsbac_slab_create_rcu(new_item_p->slabname,
			sizeof(struct rsbac_list_item_t) + info_p->desc_size + info_p->data_size);
	} else {
		new_item_p->slabname = NULL;
		new_item_p->slab = NULL;
	}
	lockdep_set_class(&new_item_p->hash_lock, &hash_lock_class);
	new_item_p->dirty = FALSE;
	if (flags & RSBAC_LIST_NO_WRITE)
		new_item_p->no_write = TRUE;
	else
		new_item_p->no_write = FALSE;
	new_item_p->self = new_item_p;
	return new_item_p;
}

/* locking needed */
static struct rsbac_list_reg_item_t *add_reg(struct rsbac_list_reg_item_t
					     *new_item_p)
{
	if (!reg_head.head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(reg_head.head, new_item_p);
		rcu_assign_pointer(reg_head.tail, new_item_p);
		rcu_assign_pointer(reg_head.curr, new_item_p);
		reg_head.count = 1;
	} else {
		new_item_p->prev = reg_head.tail;
		new_item_p->next = NULL;
		rcu_assign_pointer(reg_head.tail->next, new_item_p);
		rcu_assign_pointer(reg_head.tail, new_item_p);
		rcu_assign_pointer(reg_head.curr, new_item_p);
		reg_head.count++;
	}
	return new_item_p;
}

/* no locking needed */
static inline struct rsbac_list_lol_reg_item_t *create_lol_reg(
		struct rsbac_list_lol_info_t *info_p,
		u_int flags,
		rsbac_list_compare_function_t *compare,
		rsbac_list_compare_function_t *subcompare,
		rsbac_list_get_conv_t *get_conv,
		rsbac_list_get_conv_t *get_subconv,
		void *def_data,
		void *def_subdata,
		char *name,
		__u32 major, __u32 minor,
		const __u8 hash_bits,
		rsbac_list_hash_function_t hash_function,
		char * old_name_base)
{
	struct rsbac_list_lol_reg_item_t *new_item_p = NULL;
	const u_int nr_hashes = BIT(hash_bits);
	int i;

	if (!(new_item_p = rsbac_smalloc_clear_unlocked(lol_reg_item_slab)))
		return NULL;
	if (!(new_item_p->hashed = rsbac_kmalloc_clear_unlocked(nr_hashes*sizeof(struct rsbac_list_lol_hashed_t)))) {
		rsbac_sfree(lol_reg_item_slab, new_item_p);
		return NULL;
	}
	for (i=0; i<nr_hashes; i++) {
		spin_lock_init(&new_item_p->hashed[i].lock);
		lockdep_set_class(&new_item_p->hashed[i].lock, &list_lock_class);
	}
	new_item_p->info = *info_p;
	if (info_p->data_size && !def_data)
		flags &= ~RSBAC_LIST_DEF_DATA;
	if (!def_subdata)
		flags &= ~RSBAC_LIST_DEF_SUBDATA;
	new_item_p->flags = flags;
	new_item_p->compare = compare;
	new_item_p->subcompare = subcompare;
	new_item_p->get_conv = get_conv;
	new_item_p->get_subconv = get_subconv;
	if ((flags & RSBAC_LIST_DEF_DATA)
	    && (info_p->data_size)
	    ) {
		new_item_p->def_data = rsbac_kmalloc_unlocked(info_p->data_size);
		if (new_item_p->def_data)
			memcpy(new_item_p->def_data, def_data,
			       info_p->data_size);
		else {
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(lol_reg_item_slab, new_item_p);
			return NULL;
		}
	} else
		new_item_p->def_data = NULL;
	if ((flags & RSBAC_LIST_DEF_SUBDATA)
	    && (info_p->subdata_size)
	   ) {
		new_item_p->def_subdata =
		    rsbac_kmalloc_unlocked(info_p->subdata_size);
		if (new_item_p->def_subdata)
			memcpy(new_item_p->def_subdata, def_subdata,
			       info_p->subdata_size);
		else {
			if (new_item_p->def_data)
				rsbac_kfree(new_item_p->def_data);
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(lol_reg_item_slab, new_item_p);
			return NULL;
		}
	} else
		new_item_p->def_subdata = NULL;
	if (name) {
		strncpy(new_item_p->name, name, RSBAC_LIST_MAX_FILENAME);
		new_item_p->name[RSBAC_LIST_MAX_FILENAME] = 0;
	} else {
		strcpy(new_item_p->name, RSBAC_LIST_NONAME);
	}
	new_item_p->hash_bits = hash_bits;
	if (flags & RSBAC_LIST_NO_MAX) {
		new_item_p->max_items_per_hash = RSBAC_LIST_MAX_NR_ITEMS_LIMIT;
		new_item_p->max_subitems = RSBAC_LIST_MAX_NR_ITEMS_LIMIT;
	} else {
		new_item_p->max_items_per_hash = RSBAC_LIST_MAX_NR_ITEMS;
		new_item_p->max_subitems = RSBAC_LIST_MAX_NR_SUBITEMS;
	}
	new_item_p->hash_function = hash_function;
	if (old_name_base) {
		strncpy(new_item_p->old_name_base, old_name_base, RSBAC_LIST_MAX_FILENAME);
		new_item_p->old_name_base[RSBAC_LIST_MAX_FILENAME] = 0;
	} else
		new_item_p->old_name_base[0] = 0;
	rwlock_init(&new_item_p->hash_lock);
	new_item_p->major = major;
	new_item_p->minor = minor;
	if (flags & RSBAC_LIST_OWN_SLAB) {
		new_item_p->slabname = rsbac_kmalloc(RSBAC_MAX_SLABNAME);
		if (!new_item_p->slabname) {
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(lol_reg_item_slab, new_item_p);
			if (new_item_p->def_data)
				rsbac_kfree(new_item_p->def_data);
			if (new_item_p->def_subdata)
				rsbac_kfree(new_item_p->def_subdata);
			return NULL;
		}
		new_item_p->subslabname = rsbac_kmalloc(RSBAC_MAX_SLABNAME);
		if (!new_item_p->subslabname) {
			rsbac_kfree(new_item_p->hashed);
			rsbac_sfree(lol_reg_item_slab, new_item_p);
			if (new_item_p->def_data)
				rsbac_kfree(new_item_p->def_data);
			if (new_item_p->def_subdata)
				rsbac_kfree(new_item_p->def_subdata);
			if (new_item_p->slabname)
				rsbac_kfree(new_item_p->slabname);
			return NULL;
		}
		if (!RSBAC_IS_AUTO_DEV(major, minor)) {
			snprintf(new_item_p->slabname,
				RSBAC_MAX_SLABNAME,
				"%s-%02u:%02u",
				name,
				major, minor);
			snprintf(new_item_p->subslabname,
				RSBAC_MAX_SLABNAME,
				"%s-s-%02u:%02u",
				name,
				major, minor);
		} else {
			strncpy(new_item_p->slabname, name, RSBAC_MAX_SLABNAME);
			snprintf(new_item_p->subslabname,
				RSBAC_MAX_SLABNAME,
				"%s-s",
				name);
		}
		new_item_p->slabname[RSBAC_MAX_SLABNAME - 1] = 0;
		new_item_p->subslabname[RSBAC_MAX_SLABNAME - 1] = 0;
		new_item_p->slab = rsbac_slab_create_rcu(new_item_p->slabname,
				sizeof(struct rsbac_list_lol_item_t) + info_p->desc_size + info_p->data_size);
		new_item_p->subslab = rsbac_slab_create_rcu(new_item_p->subslabname,
				sizeof(struct rsbac_list_item_t) + info_p->subdesc_size + info_p->subdata_size);
	} else {
		new_item_p->slabname = NULL;
		new_item_p->subslabname = NULL;
		new_item_p->slab = NULL;
		new_item_p->subslab = NULL;
	}
	lockdep_set_class(&new_item_p->hash_lock, &hash_lock_class);
	new_item_p->dirty = FALSE;
	if (flags & RSBAC_LIST_NO_WRITE)
		new_item_p->no_write = TRUE;
	else
		new_item_p->no_write = FALSE;
	new_item_p->self = new_item_p;
	return new_item_p;
}

/* locking needed */
static struct rsbac_list_lol_reg_item_t *add_lol_reg(struct
						     rsbac_list_lol_reg_item_t
						     *new_item_p)
{
	if (!lol_reg_head.head) {
		new_item_p->prev = NULL;
		new_item_p->next = NULL;
		rcu_assign_pointer(lol_reg_head.head, new_item_p);
		rcu_assign_pointer(lol_reg_head.tail, new_item_p);
		rcu_assign_pointer(lol_reg_head.curr, new_item_p);
		lol_reg_head.count = 1;
	} else {
		new_item_p->prev = lol_reg_head.tail;
		new_item_p->next = NULL;
		rcu_assign_pointer(lol_reg_head.tail->next, new_item_p);
		rcu_assign_pointer(lol_reg_head.tail, new_item_p);
		rcu_assign_pointer(lol_reg_head.curr, new_item_p);
		lol_reg_head.count++;
	}
	return new_item_p;
}

/* Removing items */

/* Call spinlocked */
static inline void do_remove_item(struct rsbac_list_reg_item_t *list,
			   struct rsbac_list_item_t *item_p,
			   u_int hash)
{
	if (unlikely(!list || !item_p))
		return;

	/* curr is no longer valid -> reset */
	if (list->hashed[hash].curr == item_p)
		rcu_assign_pointer(list->hashed[hash].curr, NULL);
	if ((list->hashed[hash].head == item_p)) {	/* item is head */
		if ((list->hashed[hash].tail == item_p)) {	/* item is head and tail = only item -> list will be empty */
			rcu_assign_pointer(list->hashed[hash].head, NULL);
			rcu_assign_pointer(list->hashed[hash].tail, NULL);
		} else {	/* item is head, but not tail -> next item becomes head */
			rcu_assign_pointer(item_p->next->prev, NULL);
			rcu_assign_pointer(list->hashed[hash].head, item_p->next);
		}
	} else {		/* item is not head */
		if ((list->hashed[hash].tail == item_p)) {	/*item is not head, but tail -> previous item becomes tail */
			rcu_assign_pointer(item_p->prev->next, NULL);
			rcu_assign_pointer(list->hashed[hash].tail, item_p->prev);
		} else {	/* item is neither head nor tail -> item is cut out */
			rcu_assign_pointer(item_p->prev->next, item_p->next);
			rcu_assign_pointer(item_p->next->prev, item_p->prev);
		}
	}
	/* adjust counter */
	list->hashed[hash].count--;
	/* now we can remove the item from memory */
	rcu_free(list, hash, item_p);
}

/* Call spinlocked */
static void remove_item(struct rsbac_list_reg_item_t *list, u_int hash, void *desc)
{
	struct rsbac_list_item_t *item_p;

	if (unlikely(!list || !desc))
		return;
	/* first we must locate the item. */
	if ((item_p = lookup_item_locked(list, hash, desc))) {
		do_remove_item(list, item_p, hash);
	}
}

/* Call spinlocked */
static void remove_all_items(struct rsbac_list_reg_item_t *list, u_int hash)
{
	struct rsbac_list_item_t *item_p;

	if (unlikely(!list || !list->hashed))
		return;
	/* cleanup all items */
	item_p = list->hashed[hash].head;
	rcu_assign_pointer(list->hashed[hash].curr, NULL);
	rcu_assign_pointer(list->hashed[hash].head, NULL);
	rcu_assign_pointer(list->hashed[hash].tail, NULL);
	list->hashed[hash].count = 0;
	rcu_free_item_chain(list, hash, item_p);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call spinlocked */
static void ta_do_remove_item(struct rsbac_list_reg_item_t *list,
			      struct rsbac_list_item_t *item_p,
			      u_int hash)
{
	if (unlikely(!list || !item_p))
		return;

	/* curr is no longer valid -> reset */
	if (list->hashed[hash].ta_curr == item_p)
		rcu_assign_pointer(list->hashed[hash].ta_curr, NULL);
	if ((list->hashed[hash].ta_head == item_p)) {	/* item is head */
		if ((list->hashed[hash].ta_tail == item_p)) {	/* item is head and tail = only item -> list will be empty */
			rcu_assign_pointer(list->hashed[hash].ta_head, NULL);
			rcu_assign_pointer(list->hashed[hash].ta_tail, NULL);
		} else {	/* item is head, but not tail -> next item becomes head */
			rcu_assign_pointer(item_p->next->prev, NULL);
			rcu_assign_pointer(list->hashed[hash].ta_head, item_p->next);
		}
	} else {		/* item is not head */
		if ((list->hashed[hash].ta_tail == item_p)) {	/*item is not head, but tail -> previous item becomes tail */
			rcu_assign_pointer(item_p->prev->next, NULL);
			rcu_assign_pointer(list->hashed[hash].ta_tail, item_p->prev);
		} else {	/* item is neither head nor tail -> item is cut out */
			rcu_assign_pointer(item_p->prev->next, item_p->next);
			rcu_assign_pointer(item_p->next->prev, item_p->prev);
		}
	}
	/* adjust counter */
	list->hashed[hash].ta_count--;
	/* now we can remove the item from memory */
	rcu_free(list, hash, item_p);
}

/* Call spinlocked */
static void ta_remove_item(const rsbac_list_ta_number_t ta_number,
			   struct rsbac_list_reg_item_t *list, u_int hash, void *desc)
{
	struct rsbac_list_item_t *item_p;

	if (unlikely(!list || !desc))
		return;
	if (ta_number) {
		remove_item(list, hash, desc);
	} else {
		/* first we must locate the item. */
		if ((item_p = ta_lookup_item_locked(ta_number, list, hash, desc))) {
			ta_do_remove_item(list, item_p, hash);
		}
	}
}

/* Call spinlocked */
static void ta_remove_all_items(struct rsbac_list_reg_item_t *list, u_int hash)
{
	struct rsbac_list_item_t *item_p;

	/* cleanup all items */
	item_p = list->hashed[hash].ta_head;
	rcu_assign_pointer(list->hashed[hash].ta_curr, NULL);
	rcu_assign_pointer(list->hashed[hash].ta_head, NULL);
	rcu_assign_pointer(list->hashed[hash].ta_tail, NULL);
	list->hashed[hash].ta_count = 0;
	rcu_free_item_chain(list, hash, item_p);
}
#endif

/* Call spinlocked */
static void do_remove_lol_subitem(struct rsbac_list_lol_item_t *sublist,
				  struct rsbac_list_item_t *item_p)
{
	if (unlikely(!sublist || !item_p))
		return;

	/* curr is no longer valid -> reset */
	if (sublist->curr == item_p)
		rcu_assign_pointer(sublist->curr, NULL);
	if ((sublist->head == item_p)) {	/* item is head */
		if ((sublist->tail == item_p)) {	/* item is head and tail = only item -> list will be empty */
			rcu_assign_pointer(sublist->head, NULL);
			rcu_assign_pointer(sublist->tail, NULL);
		} else {	/* item is head, but not tail -> next item becomes head */
			rcu_assign_pointer(item_p->next->prev, NULL);
			rcu_assign_pointer(sublist->head, item_p->next);
		}
	} else {		/* item is not head */
		if ((sublist->tail == item_p)) {	/*item is not head, but tail -> previous item becomes tail */
			rcu_assign_pointer(item_p->prev->next, NULL);
			rcu_assign_pointer(sublist->tail, item_p->prev);
		} else {	/* item is neither head nor tail -> item is cut out */
			rcu_assign_pointer(item_p->prev->next, item_p->next);
			rcu_assign_pointer(item_p->next->prev, item_p->prev);
		}
	}
	/* adjust counter */
	sublist->count--;
	/* free call is in calling function */
}

/* Call spinlocked */
static void remove_lol_subitem(struct rsbac_list_lol_reg_item_t *list,
			       u_int hash,
			       struct rsbac_list_lol_item_t *sublist,
			       void *subdesc)
{
	struct rsbac_list_item_t *subitem_p;

	if (unlikely(!list || !sublist || !subdesc))
		return;

	/* first we must locate the item. */
	if ((subitem_p = lookup_lol_subitem_locked(list, sublist, subdesc))) {
		do_remove_lol_subitem(sublist, subitem_p);
		rcu_free_lol_sub(list, hash, subitem_p);
	}
}


/* Call spinlocked */
static void do_remove_lol_item(struct rsbac_list_lol_reg_item_t *list,
			       struct rsbac_list_lol_item_t *item_p,
			       u_int hash)
{
	if (unlikely(!list || !item_p))
		return;

	/* curr is no longer valid -> reset */
	if (list->hashed[hash].curr == item_p)
		rcu_assign_pointer(list->hashed[hash].curr, NULL);
	if ((list->hashed[hash].head == item_p)) {	/* item is head */
		if ((list->hashed[hash].tail == item_p)) {	/* item is head and tail = only item -> list will be empty */
			rcu_assign_pointer(list->hashed[hash].head, NULL);
			rcu_assign_pointer(list->hashed[hash].tail, NULL);
		} else {	/* item is head, but not tail -> next item becomes head */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->next) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid next!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->next->prev, NULL);
				rcu_assign_pointer(list->hashed[hash].head, item_p->next);
			}
		}
	} else {		/* item is not head */
		if ((list->hashed[hash].tail == item_p)) {	/*item is not head, but tail -> previous item becomes tail */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->prev) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid prev!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->prev->next, NULL);
				rcu_assign_pointer(list->hashed[hash].tail, item_p->prev);
			}
		} else {	/* item is neither head nor tail -> item is cut out */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->prev) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid prev!\n",
					     list->name);
			} else if (!item_p->next) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid next!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->prev->next, item_p->next);
				rcu_assign_pointer(item_p->next->prev, item_p->prev);
			}
		}
	}
	/* adjust counter */
	list->hashed[hash].count--;

	rcu_free_lol_subitem_chain(list, hash, item_p->head);
	rcu_free_lol(list, hash, item_p);
}

/* Call spinlocked */
static void remove_lol_item(struct rsbac_list_lol_reg_item_t *list,
			    u_int hash,
			    void *desc)
{
	struct rsbac_list_lol_item_t *item_p;

	if (unlikely(!list || !desc))
		return;

	/* first we must locate the item. */
	if ((item_p = lookup_lol_item_locked(list, hash, desc))) {
		do_remove_lol_item(list, item_p, hash);
	}
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call spinlocked */
static void ta_do_remove_lol_item(struct rsbac_list_lol_reg_item_t *list,
				  struct rsbac_list_lol_item_t *item_p,
				  u_int hash)
{
	if (unlikely(!list || !item_p))
		return;

	/* curr is no longer valid -> reset */
	if (list->hashed[hash].ta_curr == item_p)
		rcu_assign_pointer(list->hashed[hash].ta_curr, NULL);
	if ((list->hashed[hash].ta_head == item_p)) {	/* item is head */
		if ((list->hashed[hash].ta_tail == item_p)) {	/* item is head and tail = only item -> list will be empty */
			rcu_assign_pointer(list->hashed[hash].ta_head, NULL);
			rcu_assign_pointer(list->hashed[hash].ta_tail, NULL);
		} else {	/* item is head, but not tail -> next item becomes head */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->next) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid next!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->next->prev, NULL);
				rcu_assign_pointer(list->hashed[hash].ta_head, item_p->next);
			}
		}
	} else {		/* item is not head */
		if ((list->hashed[hash].ta_tail == item_p)) {	/*item is not head, but tail -> previous item becomes tail */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->prev) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid prev!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->prev->next, NULL);
				rcu_assign_pointer(list->hashed[hash].ta_tail, item_p->prev);
			}
		} else {	/* item is neither head nor tail -> item is cut out */
#ifdef CONFIG_RSBAC_DEBUG
			if (!item_p->prev) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid prev!\n",
					     list->name);
			} else if (!item_p->next) {	/* list corrupted! */
				rsbac_printk(KERN_WARNING "do_remove_lol_item(): list %s corrupted: invalid next!\n",
					     list->name);
			} else
#endif
			{
				rcu_assign_pointer(item_p->prev->next, item_p->next);
				rcu_assign_pointer(item_p->next->prev, item_p->prev);
			}
		}
	}
	/* adjust counter */
	list->hashed[hash].ta_count--;

	rcu_free_lol_subitem_chain(list, hash, item_p->head);
	rcu_free_lol(list, hash, item_p);
}

/* Call spinlocked */
static void ta_remove_lol_item(const rsbac_list_ta_number_t ta_number,
			       struct rsbac_list_lol_reg_item_t *list,
			       u_int hash,
			       void *desc)
{
	struct rsbac_list_lol_item_t *item_p;

	if (unlikely(!list || !desc))
		return;

	/* first we must locate the item. */
	if ((item_p = ta_lookup_lol_item_locked(ta_number, list, hash, desc))) {
		ta_do_remove_lol_item(list, item_p, hash);
	}
}
#endif

/* Call spinlocked */
static void remove_all_lol_subitems(struct rsbac_list_lol_reg_item_t *list,
				u_int hash,
				struct rsbac_list_lol_item_t *sublist)
{
	struct rsbac_list_item_t *subitem_p;

	subitem_p = sublist->head;
	rcu_assign_pointer(sublist->curr, NULL);
	rcu_assign_pointer(sublist->head, NULL);
	rcu_assign_pointer(sublist->tail, NULL);
	sublist->count = 0;
	rcu_free_lol_subitem_chain(list, hash, subitem_p);
}

/* Call spinlocked */
static void remove_all_lol_items(struct rsbac_list_lol_reg_item_t *list, u_int hash)
{
	struct rsbac_list_lol_item_t *item_p;

	if (unlikely(!list || !list->hashed))
		return;
	item_p = list->hashed[hash].head;
	rcu_assign_pointer(list->hashed[hash].curr, NULL);
	rcu_assign_pointer(list->hashed[hash].head, NULL);
	rcu_assign_pointer(list->hashed[hash].tail, NULL);
	list->hashed[hash].count = 0;
	rcu_free_lol_item_chain(list, hash, item_p);
}

#ifdef CONFIG_RSBAC_LIST_TRANS
/* Call spinlocked */
static void ta_remove_all_lol_items(struct rsbac_list_lol_reg_item_t *list,
				u_int hash)
{
	struct rsbac_list_lol_item_t *item_p;

	/* cleanup all items */
	item_p = list->hashed[hash].ta_head;
	rcu_assign_pointer(list->hashed[hash].ta_curr, NULL);
	rcu_assign_pointer(list->hashed[hash].ta_head, NULL);
	rcu_assign_pointer(list->hashed[hash].ta_tail, NULL);
	list->hashed[hash].ta_count = 0;
	rcu_free_lol_item_chain(list, hash, item_p);
}
#endif

/* Remove registration items */

/* no locking needed */
static void clear_reg(struct rsbac_list_reg_item_t *reg_item_p)
{
	if (likely(reg_item_p)) {
		int i;
	        struct rsbac_list_item_t *item_p;
	        struct rsbac_list_item_t *new_item_p;
		const u_int nr_hashes = BIT(reg_item_p->hash_bits);

		/* now we can remove the item from memory */
		synchronize_rcu();
		for (i=0; i<nr_hashes; i++) {
			item_p = reg_item_p->hashed[i].head;
			while(item_p) {
				new_item_p = item_p->next;
				rsbac_sfree(reg_item_p->slab, item_p);
				item_p = new_item_p;
			}
#ifdef CONFIG_RSBAC_LIST_TRANS
			if(reg_item_p->hashed[i].ta_copied) {
				item_p = reg_item_p->hashed[i].ta_head;
				while(item_p) {
					new_item_p = item_p->next;
					rsbac_sfree(reg_item_p->slab, item_p);
					item_p = new_item_p;
				}
			}
#endif
		}
		if (reg_item_p->def_data)
			rsbac_kfree(reg_item_p->def_data);
		if (reg_item_p->slab)
			rsbac_slab_destroy(reg_item_p->slab);
		if (reg_item_p->slabname)
			rsbac_kfree(reg_item_p->slabname);
		if (reg_item_p->hashed)
			rsbac_kfree(reg_item_p->hashed);
		rsbac_sfree(reg_item_slab, reg_item_p);
	}
}

/* locking needed */
static void remove_reg(struct rsbac_list_reg_item_t *reg_item_p)
{
	/* first we must locate the item. */
	if (reg_item_p && (reg_item_p->self == reg_item_p)) {/* item found and valid */
		/* protect against reuse */
		reg_item_p->self = NULL;
		if ((reg_head.head == reg_item_p)) {	/* item is head */
			if ((reg_head.tail == reg_item_p)) {	/* item is head and tail = only item -> list will be empty */
				rcu_assign_pointer(reg_head.head, NULL);
				rcu_assign_pointer(reg_head.tail, NULL);
			} else {	/* item is head, but not tail -> next item becomes head */
				reg_item_p->next->prev = NULL;
				rcu_assign_pointer(reg_head.head, reg_item_p->next);
			}
		} else {	/* item is not head */
			if ((reg_head.tail == reg_item_p)) {	/*item is not head, but tail -> previous item becomes tail */
				reg_item_p->prev->next = NULL;
				rcu_assign_pointer(reg_head.tail, reg_item_p->prev);
			} else {	/* item is neither head nor tail -> item is cut out */
				reg_item_p->prev->next = reg_item_p->next;
				reg_item_p->next->prev = reg_item_p->prev;
			}
		}

		/* curr is no longer valid -> reset */
		reg_head.curr = NULL;
		/* adjust counter */
		reg_head.count--;
	}	/* end of if: item was found */
}

/* no locking needed */
static void clear_lol_reg(struct rsbac_list_lol_reg_item_t *reg_item_p)
{
	int i;

	if (likely(reg_item_p)) {
	        struct rsbac_list_lol_item_t *lol_item_p;
	        struct rsbac_list_lol_item_t *new_lol_item_p;
	        struct rsbac_list_item_t * lol_subitem_p;
	        struct rsbac_list_item_t * new_lol_subitem_p;
		const u_int nr_hashes = BIT(reg_item_p->hash_bits);

		/* now we can remove the item from memory */
		synchronize_rcu();
		for (i=0; i<nr_hashes; i++) {
			lol_item_p = reg_item_p->hashed[i].head;
			while(lol_item_p) {
				lol_subitem_p = lol_item_p->head;
				while (lol_subitem_p) {
					new_lol_subitem_p = lol_subitem_p->next;
					rsbac_sfree(reg_item_p->subslab, lol_subitem_p);
					lol_subitem_p = new_lol_subitem_p;
				}
				new_lol_item_p = lol_item_p->next;
				rsbac_sfree(reg_item_p->slab, lol_item_p);
				lol_item_p = new_lol_item_p;
			}
#ifdef CONFIG_RSBAC_LIST_TRANS
			if(reg_item_p->hashed[i].ta_copied) {
				lol_item_p = reg_item_p->hashed[i].ta_head;
				while(lol_item_p) {
					lol_subitem_p = lol_item_p->head;
					while (lol_subitem_p) {
						new_lol_subitem_p = lol_subitem_p->next;
						rsbac_sfree(reg_item_p->subslab, lol_subitem_p);
						lol_subitem_p = new_lol_subitem_p;
					}
					new_lol_item_p = lol_item_p->next;
					rsbac_sfree(reg_item_p->slab, lol_item_p);
					lol_item_p = new_lol_item_p;
				}
			}
#endif
		}
		if (reg_item_p->def_data)
			rsbac_kfree(reg_item_p->def_data);
		if (reg_item_p->def_subdata)
			rsbac_kfree(reg_item_p->def_subdata);
		if (reg_item_p->slab)
			rsbac_slab_destroy(reg_item_p->slab);
		if (reg_item_p->subslab)
			rsbac_slab_destroy(reg_item_p->subslab);
		if (reg_item_p->slabname)
			rsbac_kfree(reg_item_p->slabname);
		if (reg_item_p->subslabname)
			rsbac_kfree(reg_item_p->subslabname);
		if (reg_item_p->hashed)
			rsbac_kfree(reg_item_p->hashed);
		rsbac_sfree(lol_reg_item_slab, reg_item_p);
	}
}

/* locking needed */
static void remove_lol_reg(struct rsbac_list_lol_reg_item_t *reg_item_p)
{
	/* first we must locate the item. */
	if (reg_item_p && (reg_item_p->self == reg_item_p)) {/* found */
		/* protect against reuse */
		reg_item_p->self = NULL;
		if ((lol_reg_head.head == reg_item_p)) {	/* item is head */
			if ((lol_reg_head.tail == reg_item_p)) {	/* item is head and tail = only item -> list will be empty */
				rcu_assign_pointer(lol_reg_head.head, NULL);
				rcu_assign_pointer(lol_reg_head.tail, NULL);
			} else {	/* item is head, but not tail -> next item becomes head */
				reg_item_p->next->prev = NULL;
				rcu_assign_pointer(lol_reg_head.head, reg_item_p->next);
			}
		} else {	/* item is not head */
			if ((lol_reg_head.tail == reg_item_p)) {	/*item is not head, but tail -> previous item becomes tail */
				reg_item_p->prev->next = NULL;
				rcu_assign_pointer(lol_reg_head.tail, reg_item_p->prev);
			} else {	/* item is neither head nor tail -> item is cut out */
				reg_item_p->prev->next = reg_item_p->next;
				reg_item_p->next->prev = reg_item_p->prev;
			}
		}

		/* curr is no longer valid -> reset */
		rcu_assign_pointer(lol_reg_head.curr, NULL);
		/* adjust counter */
		lol_reg_head.count--;
	}	/* end of if: item was found */
}

#define touch(x)

#define lol_touch(x)

/********************/
/* Read/Write       */
/********************/

/* call unlocked */
static int do_read_list(struct rsbac_list_reg_item_t *list,
	char * name,
	rsbac_boolean_t backup)
{
	long file_fd;
	int err = 0;
	int tmperr;
	int converr;
	rsbac_version_t list_version;
	u_long read_count = 0;
	char *old_buf = NULL;
	char *new_buf = NULL;
	char *old_data;
	char *new_data;
	struct rsbac_list_info_t *list_info_p;
	rsbac_list_count_t list_count;
	rsbac_time_t timestamp;
	struct rsbac_nanotime_t lastchange;
	rsbac_time_t max_age = 0;
	rsbac_list_conv_function_t *conv = NULL;
	rsbac_boolean_t timeout = FALSE;
	u_int hash = 0;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (unlikely(!list_info_p))
		return -RSBAC_ENOMEM;
	/* open file */
	if ((file_fd = rsbac_read_open(name, list->major, list->minor)) < 0) {
		goto double_free;
	}

	/* OK, now we can start reading */
	/* There is a read function for this file, so check info and read as
	 * many items as possible. A positive return value means a read success,
	 * 0 end of file and a negative value an error. */

	/* check gen-list on-disk version */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) & list_version,
				sizeof(list_version));
	/* error? */
	if (tmperr < sizeof(list_version)) {
		rsbac_printk(KERN_WARNING "do_read_list(): read error %i from file when reading list version!\n", tmperr);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}
	/* if wrong list on-disk version, fail */
	switch (list_version) {
	case RSBAC_LIST_DISK_VERSION:
	case RSBAC_LIST_DISK_OLD_VERSION:
		break;
	default:
		rsbac_printk(KERN_WARNING "do_read_list(): wrong on-disk list version %u in file %s, expected %u - error!\n",
			     list_version,
			     name, RSBAC_LIST_DISK_VERSION);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* get timestamp */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) & timestamp,
				sizeof(timestamp));
	/* error? */
	if (tmperr < sizeof(timestamp)) {
		rsbac_printk(KERN_WARNING "do_read_list(): timestamp read error %i from file %s!\n",
			     tmperr,
			     name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* get list info */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) list_info_p,
				sizeof(*list_info_p));
	/* error? */
	if (tmperr < sizeof(*list_info_p)) {
		rsbac_printk(KERN_WARNING "do_read_list(): list info read error %i from file %s!\n",
			     tmperr,
			     name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* list timed out? System time is measured in seconds. */
	if (list_info_p->max_age
	    && (timestamp + list_info_p->max_age) <= RSBAC_CURRENT_TIME)
		timeout = TRUE;

	/* Valid key? */
	if (list_info_p->key != list->info.key) {
		if (timeout) {
			rsbac_printk(KERN_WARNING "do_read_list(): accessing timed out list %s with wrong key, ignoring old contents!\n",
				     name);
			goto end_read;
		} else {
			rsbac_printk(KERN_WARNING "do_read_list(): try to access list %s with wrong key!\n",
				     name);
			err = -EPERM;
			goto end_read;
		}
	}

	/* skip the rest, if ignore is requested */
	if (list->flags & RSBAC_LIST_IGNORE_OLD)
		goto end_read;

	switch (list_version) {
	case RSBAC_LIST_DISK_VERSION:
		tmperr = rsbac_read_file(file_fd,
					(char *) &lastchange,
					sizeof(lastchange));
		/* error? */
		if (tmperr < sizeof(lastchange)) {
			rsbac_printk(KERN_WARNING "do_read_list(): lastchange read error %i from file %s!\n",
				     tmperr,
				     name);
			err = -RSBAC_EREADFAILED;
			goto end_read;
		}
		break;
	case RSBAC_LIST_DISK_OLD_VERSION:
		break;
	default:
		break;
	}
	/* if wrong list version, try to get_conv */
	if (list_info_p->version != list->info.version) {
		if (list->get_conv)
			conv = list->get_conv(list_info_p->version);
		if (!conv) {
			if (timeout) {
				rsbac_printk(KERN_WARNING "do_read_list(): accessing timed out list %s without conversion function, ignoring old contents!\n",
					     name);
				goto end_read;
			} else {
				/* complain and set error, if ignore is not requested */
				if (!
				    (list->
				     flags &
				     RSBAC_LIST_IGNORE_UNSUPP_VERSION)) {
					rsbac_printk(KERN_WARNING "do_read_list(): cannot convert list version %u of file %s to version %u!\n",
						     list_info_p->version,
						     name,
						     list->info.version);
					err = -RSBAC_EINVALIDVERSION;
				}
				goto end_read;
			}
		} else {
			rsbac_printk(KERN_WARNING "do_read_list(): converting list version %u of file %s on device %02u:%02u to version %u!\n",
				     list_info_p->version,
				     name,
				     list->major, list->minor,
				     list->info.version);
		}
	} else {		/* same version needs same sizes */

		if ((list_info_p->desc_size != list->info.desc_size)
		    || (list_info_p->data_size != list->info.data_size)
		    ) {
			if (timeout) {
				rsbac_printk(KERN_WARNING "do_read_list(): accessing timed out list %s with wrong desc or data size, ignoring old contents!\n",
					     name);
				goto end_read;
			} else {
				rsbac_printk(KERN_WARNING "do_read_list(): desc or data size mismatch on list %s!\n",
					     name);
				err = -RSBAC_EINVALIDLIST;
				goto end_read;
			}
		}
	}

	/* get list count */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) & list_count,
				sizeof(list_count));
	/* error? */
	if (tmperr < sizeof(list_count)) {
		rsbac_printk(KERN_WARNING "do_read_list(): list count read error %i from file %s!\n",
			     tmperr,
			     name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* alloc mem for old and converted item */
	old_buf = rsbac_kmalloc_unlocked(list_info_p->desc_size + list_info_p->data_size);
	if (!old_buf) {
		rsbac_printk(KERN_WARNING "do_read_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	new_buf = rsbac_kmalloc_unlocked(list->info.desc_size + list->info.data_size);
	if (unlikely(!new_buf)) {
		rsbac_printk(KERN_WARNING "do_read_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	/* calculate data pointers */
	if (list_info_p->data_size)
		old_data = old_buf + list_info_p->desc_size;
	else
		old_data = NULL;
	if (list->info.data_size)
		new_data = new_buf + list->info.desc_size;
	else
		new_data = NULL;

	/* actual reading */
	do {
		tmperr = rsbac_read_file(file_fd,
					(char *) &max_age,
					sizeof(max_age));
		if (conv) {
			tmperr = rsbac_read_file(file_fd,
						old_buf,
						list_info_p->
						desc_size +
						list_info_p->data_size);
			if (tmperr > 0) {	/* convert */
				converr = conv(old_buf, old_data,
					       new_buf, new_data);
				if (converr)
					tmperr = converr;
			}
		} else {
			tmperr = rsbac_read_file(file_fd,
						    new_buf,
						    list->info.desc_size +
						    list->info.data_size);
		}
		/* if successful, add item */
		if (tmperr > 0) {
			if(list->hash_function)
				hash = list->hash_function(new_buf, list->hash_bits);
			/* no need to lock, list is not yet published */
			if (!backup || !lookup_item_locked(list, hash, new_buf))
				add_item(list, hash, max_age, new_buf, new_data);
			/* allow access */
			read_count++;
/*
			rsbac_pr_debug(lists, "read item %i\n", user_aci.id);
*/
		}
	}
	while (tmperr > 0);	/* end of do */

	if (tmperr < 0) {
		rsbac_printk(KERN_WARNING "do_read_list(): read error %i from file %s!\n",
			     tmperr,
			     name);
		err = -RSBAC_EREADFAILED;
	}

	if (read_count != list_count) {
		rsbac_printk(KERN_WARNING "do_read_list(): read %lu, expected %u items from file %s!\n",
			     read_count, list_count, name);
		err = -RSBAC_EREADFAILED;
	}

end_read:
	if (old_buf)
		rsbac_kfree(old_buf);
	if (new_buf)
		rsbac_kfree(new_buf);

	rsbac_pr_debug(lists, "%lu entries read.\n", read_count);
	/* We do not need this file any more */
	rsbac_read_close(file_fd);

double_free:
	rsbac_kfree(list_info_p);

	if (   err
	    && (err != -RSBAC_ENOTFOUND)
	    && !backup
	    && rsbac_list_recover
	   ) {
	   	char * bname;

		rsbac_list_read_errors++;
		bname = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
		if (!bname)
			return -RSBAC_ENOMEM;
		rsbac_printk(KERN_WARNING "restoring list %s from device %02u:%02u failed with error %s, rsbac_list_recover is set, so retrying with backup list.\n",
			name,
			list->major, list->minor,
			get_error_name(bname, err));
		sprintf(bname, "%sb", name);
		err = do_read_list(list, bname, TRUE);
		if (   err
		    && (err != -RSBAC_ENOTFOUND)
		    && rsbac_list_recover
		   ) {
			rsbac_printk(KERN_WARNING "restoring list %s backup from device %02u:%02u failed with error %s, rsbac_list_recover is set, so returning that list is fine.\n",
				name,
				list->major, list->minor,
				get_error_name(bname, err));
			err = 0;
		}
		list->dirty = TRUE;
		rsbac_kfree(bname);
	}

	return err;
}

/* call unlocked */
static int read_list(struct rsbac_list_reg_item_t *list)
{
  int res;
  u_int flags;

  flags = list->flags;
  list->flags |= RSBAC_LIST_NO_MAX;
  res = do_read_list(list, list->name, FALSE);
  if((res == -RSBAC_ENOTFOUND) && list->old_name_base[0]) {
	char name[RSBAC_MAXNAMELEN];
	int i;

	rsbac_printk(KERN_INFO "read_list(): list %s on device %02u:%02u not found, trying numbered lists 0 to %u with old name base '%s'\n",
			list->name, list->major, list->minor, RSBAC_LIST_MAX_OLD_HASH-1, list->old_name_base);
	for (i=0; i<RSBAC_LIST_MAX_OLD_HASH; i++) {
		sprintf(name, "%s%u", list->old_name_base, i);
		res = do_read_list(list, name, FALSE);
		if(res && (res != -RSBAC_ENOTFOUND))
			return res;
	}
	list->dirty = TRUE;
  }
  list->flags = flags;
  return res;
}

/* call unlocked */
static int do_read_lol_list(struct rsbac_list_lol_reg_item_t *list,
	char * name,
	rsbac_boolean_t backup)
{
	long file_fd;
	int err = 0;
	int tmperr;
	int converr;
	rsbac_version_t list_version;
	u_long read_count = 0;
	u_long sublen;
	u_long i;
	char *old_buf = NULL;
	char *new_buf = NULL;
	char *old_data;
	char *new_data;
	char *old_subbuf = NULL;
	char *new_subbuf = NULL;
	char *old_subdata;
	char *new_subdata;
	struct rsbac_list_lol_info_t *list_info_p;
	rsbac_list_count_t list_count;
	rsbac_time_t timestamp;
	struct rsbac_nanotime_t lastchange;
	rsbac_time_t max_age = 0;
	rsbac_list_conv_function_t *conv = NULL;
	rsbac_list_conv_function_t *subconv = NULL;
	rsbac_boolean_t timeout = FALSE;
	struct rsbac_list_lol_item_t *item_p;
	u_int hash = 0;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (unlikely(!list_info_p))
		return -RSBAC_ENOMEM;
	/* open file */
	if ((file_fd = rsbac_read_open(name, list->major, list->minor)) < 0) {
		goto double_free;
	}

	/* OK, now we can start reading */
	/* There is a read function for this file, so check info and read as
	 * many items as possible. A positive return value means a read success,
	 * 0 end of file and a negative value an error. */

	/* check gen-list on-disk version */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) & list_version,
				sizeof(list_version));
	/* error? */
	if (tmperr < sizeof(list_version)) {
		printk(KERN_WARNING
			"do_read_lol_list(): read error %i from file!\n",
			tmperr);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}
	/* if wrong list on-disk version, fail */
	switch (list_version) {
	case RSBAC_LIST_DISK_VERSION:
	case RSBAC_LIST_DISK_OLD_VERSION:
		break;
	default:
		rsbac_printk(KERN_WARNING "do_read_lol_list(): wrong on-disk list version %u in file %s, expected %u - error!\n",
			     list_version,
			     name, RSBAC_LIST_DISK_VERSION);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* get timestamp */
	tmperr = rsbac_read_file(file_fd,
				    (__u8 *) & timestamp,
				    sizeof(timestamp));
	/* error? */
	if (tmperr < sizeof(timestamp)) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): timestamp read error %i from file %s!\n",
				tmperr,
				name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* get list info */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) list_info_p,
				sizeof(*list_info_p));
	/* error? */
	if (tmperr < sizeof(*list_info_p)) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): list info read error %i from file %s!\n",
				tmperr,
				name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* list timed out? System time is measured in seconds. */
	if (list_info_p->max_age
	    && (timestamp + list_info_p->max_age) <= RSBAC_CURRENT_TIME)
		timeout = TRUE;

	/* Valid key? */
	if (list_info_p->key != list->info.key) {
		if (timeout) {
			rsbac_printk(KERN_WARNING "do_read_lol_list(): accessing timed out list %s with wrong key, ignoring old contents!\n",
				     name);
			goto end_read;
		} else {
			rsbac_printk(KERN_WARNING "do_read_lol_list(): try to access list %s with wrong key!\n",
				     name);
			err = -EPERM;
			goto end_read;
		}
	}

	/* skip the rest, if ignore is requested */
	if (list->flags & RSBAC_LIST_IGNORE_OLD)
		goto end_read;

	switch (list_version) {
	case RSBAC_LIST_DISK_VERSION:
		tmperr = rsbac_read_file(file_fd,
					(char *) &lastchange,
					sizeof(lastchange));
		/* error? */
		if (tmperr < sizeof(lastchange)) {
			rsbac_printk(KERN_WARNING "do_read_lol_list(): lastchange read error %i from file %s!\n",
					tmperr,
					name);
			err = -RSBAC_EREADFAILED;
			goto end_read;
		}
		break;
	case RSBAC_LIST_DISK_OLD_VERSION:
		break;
	default:
		break;
	}
	/* if wrong list version, try to get_conv */
	if (list_info_p->version != list->info.version) {
		if (list->get_conv)
			conv = list->get_conv(list_info_p->version);
		if (list->get_subconv)
			subconv = list->get_subconv(list_info_p->version);
		if (!conv || !subconv) {
			if (timeout) {
				rsbac_printk(KERN_WARNING "do_read_lol_list(): accessing timed out list %s without both conversion functions, ignoring old contents!\n",
					     name);
				goto end_read;
			} else {
				/* complain and set error, if ignore is not requested */
				if (!
				    (list->
				     flags &
				     RSBAC_LIST_IGNORE_UNSUPP_VERSION)) {
					rsbac_printk(KERN_WARNING "do_read_lol_list(): cannot convert list version %u of file %s to version %u!\n",
						     list_info_p->version,
						     name,
						     list->info.version);
					err = -RSBAC_EINVALIDVERSION;
				}
				goto end_read;
			}
		} else {
			rsbac_printk(KERN_WARNING "do_read_lol_list(): converting list version %u of file %s on device %02u:%02u to version %u!\n",
				     list_info_p->version,
				     name,
				     list->major, list->minor,
				     list->info.version);
		}
	} else {		/* same version needs same sizes */

		if ((list_info_p->desc_size != list->info.desc_size)
		    || (list_info_p->data_size != list->info.data_size)
		    || (list_info_p->subdesc_size !=
			list->info.subdesc_size)
		    || (list_info_p->subdata_size !=
			list->info.subdata_size)
		    ) {
			if (timeout) {
				rsbac_printk(KERN_WARNING "do_read_lol_list(): accessing timed out list %s with wrong desc or data size(s), ignoring old contents!\n",
					     name);
				goto end_read;
			} else {
				rsbac_printk(KERN_WARNING "do_read_lol_list(): desc or data size mismatch on list %s!\n",
					     name);
				err = -RSBAC_EINVALIDLIST;
				goto end_read;
			}
		}
	}

	/* get list count */
	tmperr = rsbac_read_file(file_fd,
				(__u8 *) & list_count,
				sizeof(list_count));
	/* error? */
	if (tmperr < sizeof(list_count)) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): list count read error %i from file %s!\n",
				tmperr,
				name);
		err = -RSBAC_EREADFAILED;
		goto end_read;
	}

	/* alloc mem for old and converted items */
	old_buf = rsbac_kmalloc_unlocked(list_info_p->desc_size + list_info_p->data_size);
	if (!old_buf) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	new_buf = rsbac_kmalloc_unlocked(list->info.desc_size + list->info.data_size);
	if (!new_buf) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	old_subbuf = rsbac_kmalloc_unlocked(list_info_p->subdesc_size +
			  list_info_p->subdata_size);
	if (!old_subbuf) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	new_subbuf = rsbac_kmalloc_unlocked(list->info.subdesc_size +
			  list->info.subdata_size);
	if (!new_subbuf) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): cannot allocate memory!\n");
		err = -RSBAC_ENOMEM;
		goto end_read;
	}
	/* calculate data pointers */
	if (list_info_p->data_size)
		old_data = old_buf + list_info_p->desc_size;
	else
		old_data = NULL;
	if (list->info.data_size)
		new_data = new_buf + list->info.desc_size;
	else
		new_data = NULL;
	if (list_info_p->subdata_size)
		old_subdata = old_subbuf + list_info_p->subdesc_size;
	else
		old_subdata = NULL;
	if (list->info.subdata_size)
		new_subdata = new_subbuf + list->info.subdesc_size;
	else
		new_subdata = NULL;

	/* actual reading */
	do {
		tmperr = rsbac_read_file(file_fd,
					(char *) &max_age,
					sizeof(max_age));
		if (conv) {
			tmperr = rsbac_read_file(file_fd,
						old_buf,
						list_info_p->desc_size + list_info_p->data_size);
			if (tmperr > 0) {	/* convert */
				converr = conv(old_buf, old_data,
					       new_buf, new_data);
				if (converr)
					tmperr = converr;
			}
		} else {
			tmperr = rsbac_read_file(file_fd,
						new_buf,
						list->info.desc_size + list->info.data_size);
		}
		/* if successful, add item */
		if (tmperr > 0) {
			if(list->hash_function)
				hash = list->hash_function(new_buf, list->hash_bits);
			/* no need to lock, list is not yet published */
			if (!backup || !(item_p = lookup_lol_item_locked(list, hash, new_buf)))
				item_p = add_lol_item(list, hash, max_age, new_buf, new_data);
			/* allow access */
			if (!item_p) {
				err = -RSBAC_ENOMEM;
				goto end_read;
			}
			read_count++;
/*
			rsbac_pr_debug(lists, "read item %i\n", user_aci.id);
*/
			tmperr = rsbac_read_file(file_fd,
						(__u8 *) & sublen,
						sizeof(sublen));
			/* if successful, read and add sublen subitems */
			if (tmperr > 0) {
				for (i = 0; i < sublen; i++) {
					tmperr = rsbac_read_file(file_fd,
								(char *) &max_age,
								sizeof(max_age));
					if (subconv) {
						tmperr = rsbac_read_file(file_fd,
								old_subbuf,
								list_info_p->subdesc_size + list_info_p->subdata_size);
						if (tmperr > 0) {	/* convert */
							converr =
							    subconv
							    (old_subbuf,
							     old_subdata,
							     new_subbuf,
							     new_subdata);
							if (converr)
								tmperr =
								    converr;
						}
					} else {
						tmperr = rsbac_read_file(file_fd,
								new_subbuf,
								list->info.subdesc_size + list->info.subdata_size);
					}
					if (tmperr > 0) {
						/* no need to lock, list is not yet published */
						if (!backup || !lookup_lol_subitem_locked(list, item_p, new_subbuf))
							if (!add_lol_subitem
							    (list, item_p, max_age,
							     new_subbuf,
							     new_subdata)) {
								rsbac_printk(KERN_WARNING "do_read_lol_list(): could not add subitem!\n");
								i = sublen;
								tmperr = -1;
							}
					} else {
						i = sublen;
						tmperr = -1;
					}
				}
			}
		}
	}
	while (tmperr > 0);	/* end of do */

	if (tmperr < 0) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): read error %i from file %s!\n",
				tmperr,
				name);
		err = -RSBAC_EREADFAILED;
	}

	if (read_count != list_count) {
		rsbac_printk(KERN_WARNING "do_read_lol_list(): read %lu, expected %u items from file %s!\n",
			     read_count, list_count, name);
		err = -RSBAC_EREADFAILED;
	}

end_read:
	if (old_buf)
		rsbac_kfree(old_buf);
	if (new_buf)
		rsbac_kfree(new_buf);
	if (old_subbuf)
		rsbac_kfree(old_subbuf);
	if (new_subbuf)
		rsbac_kfree(new_subbuf);

	rsbac_pr_debug(lists, "%lu entries read.\n", read_count);
	/* We do not need this file any more */
	rsbac_read_close(file_fd);

double_free:
	rsbac_kfree(list_info_p);

	if (   err
	    && (err != -RSBAC_ENOTFOUND)
	    && !backup
	    && rsbac_list_recover
	   ) {
	   	char * bname;

		rsbac_list_read_errors++;
		bname = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
		if (!bname)
			return -RSBAC_ENOMEM;
		rsbac_printk(KERN_WARNING "restoring list of lists %s from device %02u:%02u failed with error %s, rsbac_list_recover is set, so retrying with backup list.\n",
			name,
			list->major, list->minor,
			get_error_name(bname, err));
		sprintf(bname, "%sb", name);
		err = do_read_lol_list(list, bname, TRUE);
		if (   err
		    && (err != -RSBAC_ENOTFOUND)
		    && rsbac_list_recover
		   ) {
			rsbac_printk(KERN_WARNING "restoring list of lists %s backup from device %02u:%02u failed with error %s, rsbac_list_recover is set, so returning that list is fine.\n",
				name,
				list->major, list->minor,
				get_error_name(bname, err));
			err = 0;
		}
		list->dirty = TRUE;
		rsbac_kfree(bname);
	}

	return err;
}				/* end of do_read_lol_list() */

/* call unlocked */
static int read_lol_list(struct rsbac_list_lol_reg_item_t *list)
{
  int res;
  u_int flags;

  flags = list->flags;
  list->flags |= RSBAC_LIST_NO_MAX;
  res = do_read_lol_list(list, list->name, FALSE);
  if((res == -RSBAC_ENOTFOUND) && list->old_name_base[0]) {
	char name[RSBAC_MAXNAMELEN];
	int i;

	rsbac_printk(KERN_INFO "read_lol_list(): list %s on device %02u:%02u not found, trying numbered lists 0 to %u with old name base '%s'\n",
			list->name, list->major, list->minor, RSBAC_LIST_LOL_MAX_OLD_HASH-1, list->old_name_base);
	for (i=0; i<RSBAC_LIST_LOL_MAX_OLD_HASH; i++) {
		sprintf(name, "%s%u", list->old_name_base, i);
		res = do_read_lol_list(list, name, FALSE);
		if(res && (res != -RSBAC_ENOTFOUND))
			return res;
	}
	list->dirty = TRUE;
  }
  list->flags = flags;
  return res;
}


#ifndef CONFIG_RSBAC_NO_WRITE
static int check_buffer(struct rsbac_list_buffer_t ** buffer_pp, u_int size)
{
	if((*buffer_pp)->len + size <= RSBAC_LIST_BUFFER_SIZE)
		return 0;
	else {
		struct rsbac_list_buffer_t * new_buffer;

		new_buffer = rsbac_kmalloc(sizeof(*new_buffer));
		if(!new_buffer)
			return -RSBAC_ENOMEM;
		new_buffer->data = rsbac_kmalloc(RSBAC_LIST_BUFFER_SIZE);
		if(!new_buffer->data) {
			kfree(new_buffer);
			return -RSBAC_ENOMEM;
		}
		rsbac_pr_debug(write, "Added a buffer\n");
		new_buffer->next = NULL;
		new_buffer->len = 0;
		(*buffer_pp)->next = new_buffer;
		*buffer_pp = new_buffer;
		return 0;
	}
}

static void free_buffers(struct rsbac_list_buffer_t * buffer)
{
	struct rsbac_list_buffer_t * next;

	while(buffer) {
		rsbac_pr_debug(write, "Freeing buffer of size %u\n",
				buffer->len);
		next = buffer->next;
		rsbac_kfree(buffer->data);
		rsbac_kfree(buffer);
		buffer = next;
	}
}

/* call unlocked */
static int fill_buffer(struct rsbac_list_reg_item_t *list,
		       struct rsbac_list_write_item_t **write_item_pp)
{
	struct rsbac_list_write_item_t *write_item_p;
	struct rsbac_list_item_t *current_p;
	struct rsbac_list_buffer_t *buffer = NULL;
	rsbac_list_count_t allcount = 0;
	rsbac_version_t list_version = RSBAC_LIST_DISK_VERSION;
	rsbac_time_t timestamp = RSBAC_CURRENT_TIME;
	int i;
	const u_int nr_hashes = BIT(list->hash_bits);

	write_item_p = rsbac_kmalloc(sizeof(*write_item_p));
	if (unlikely(!write_item_p)) {
		*write_item_pp = NULL;
		return -RSBAC_ENOMEM;
	}

	/* fill write_item */
	write_item_p->prev = NULL;
	write_item_p->next = NULL;
	write_item_p->list = list;
	write_item_p->buffer = NULL;
	strncpy(write_item_p->name, list->name, RSBAC_LIST_MAX_FILENAME);
	write_item_p->name[RSBAC_LIST_MAX_FILENAME] = 0;
	write_item_p->major = list->major;
	write_item_p->minor = list->minor;

	buffer = rsbac_kmalloc(sizeof(*buffer));
	if (unlikely(!buffer)) {
		rsbac_kfree(write_item_p);
		*write_item_pp = NULL;
		return -RSBAC_ENOMEM;
	}
	buffer->data = rsbac_kmalloc(RSBAC_LIST_BUFFER_SIZE);
	if (unlikely(!buffer->data)) {
		rsbac_kfree(buffer);
		rsbac_kfree(write_item_p);
		*write_item_pp = NULL;
		return -RSBAC_ENOMEM;
	}
	write_item_p->buffer = buffer;
	buffer->len = 0;
	buffer->next = NULL;
	/* copy version */
	memcpy(buffer->data, &list_version, sizeof(list_version));
	buffer->len = sizeof(list_version);
	/* copy timestamp */
	memcpy(buffer->data + buffer->len,
	       &timestamp, sizeof(timestamp));
	buffer->len += sizeof(timestamp);
	/* copy info */
	memcpy(buffer->data + buffer->len,
	       &list->info, sizeof(list->info));
	buffer->len += sizeof(list->info);

	/* Protect list */
	rcu_read_lock();
	for (i=0; i<nr_hashes; i++)
		allcount += list->hashed[i].count;
	/* copy lastchange */
	memcpy(buffer->data + buffer->len,
	       &list->lastchange, sizeof(list->lastchange));
	buffer->len += sizeof(list->lastchange);
	/* copy count */
	memcpy(buffer->data + buffer->len,
	       &allcount, sizeof(allcount));
	buffer->len += sizeof(allcount);
	/* copy list */
	for (i=0; i<nr_hashes; i++) {
		current_p = list->hashed[i].head;
		while (current_p) {
			if (unlikely(check_buffer(&buffer, sizeof(current_p->max_age) + list->info.desc_size + list->info.data_size))) {
				/* unprotect this list */
				rcu_read_unlock();
				free_buffers(write_item_p->buffer);
				rsbac_kfree(write_item_p);
				*write_item_pp = NULL;
				return -RSBAC_ENOMEM;
			}
			memcpy(buffer->data + buffer->len,
			       &current_p->max_age, sizeof(current_p->max_age));
			buffer->len += sizeof(current_p->max_age);
			memcpy(buffer->data + buffer->len,
			       ((char *) current_p) + sizeof(*current_p),
			       list->info.desc_size + list->info.data_size);
			buffer->len += list->info.desc_size + list->info.data_size;
			current_p = current_p->next;
		}
	}
	rcu_read_unlock();

	*write_item_pp = write_item_p;

	return 0;
}

/* call unlocked */
static int rsbac_list_write_buffers(struct rsbac_list_write_head_t write_head)
{
	long file_fd;
	int count = 0;
	u_int written;
	u_long all_written;
	u_long bytes;
	u_int bufcount;
	int tmperr = 0;
	struct rsbac_list_buffer_t * buffer;
	struct rsbac_list_write_item_t *write_item_p;
	struct rsbac_list_write_item_t *next_item_p;

	write_item_p = write_head.head;
	while (write_item_p) {
		rsbac_pr_debug(write, "write list %s on device %02u:%02u.\n",
			       write_item_p->name,
			       write_item_p->major, write_item_p->minor);
		/* open file */
		if ((file_fd = rsbac_write_open(write_item_p->name,
					        write_item_p->major, write_item_p->minor)) < 0) {
			if (file_fd != -RSBAC_ENOTWRITABLE) {
				rsbac_printk(KERN_WARNING "rsbac_list_write_buffers(): opening file %s on device %02u:%02u failed with error %i!\n",
					     write_item_p->name,
					     write_item_p->major, write_item_p->minor,
					     file_fd);
			}
			count = file_fd;
			goto out_free_all;
		}

		/* OK, now we can start writing the buffer. */
		buffer = write_item_p->buffer;
		all_written = 0;
		bufcount = 0;
		while (buffer && (tmperr >= 0)) {
			rsbac_pr_debug(write, "Writing list %s, buffer %u with size %u\n",
					write_item_p->name, bufcount, buffer->len);
			bufcount++;
			written = 0;
			while ((written < buffer->len) && (tmperr >= 0)) {
				bytes = buffer->len - written;
				tmperr = rsbac_write_file(file_fd,
							buffer->data + written,
							bytes);
				if (tmperr > 0) {
					written += tmperr;
				}
			}
			all_written += written;
			buffer = buffer->next;
		}
		/* End of write access */
		rsbac_write_close(file_fd);
		if (tmperr < 0) {
			rsbac_printk(KERN_WARNING "rsbac_list_write_buffers(): write error %i on device %02u:%02u file %s!\n",
				     tmperr,
				     write_item_p->major, write_item_p->minor,
				     write_item_p->name);
			count = tmperr;
			goto out_free_all;
		} else
			count++;

		rsbac_pr_debug(write, "%lu bytes from %u buffers written.\n",
			       all_written, bufcount);

		free_buffers(write_item_p->buffer);
		next_item_p = write_item_p->next;
		rsbac_kfree(write_item_p);
		write_item_p = next_item_p;
	}
	return count;

out_free_all:
    /* Mark unwritten lists dirty and free everything */
    while(write_item_p)
      {
        if(write_item_p->list->self == write_item_p->list)
          write_item_p->list->dirty = TRUE;
	free_buffers(write_item_p->buffer);
        next_item_p = write_item_p->next;
        rsbac_kfree(write_item_p);
        write_item_p = next_item_p;
      }
    return count;
}

/* call unlocked */
static int fill_lol_buffer(struct rsbac_list_lol_reg_item_t *list,
			   struct rsbac_list_lol_write_item_t
			   **write_item_pp)
{
	struct rsbac_list_lol_write_item_t *write_item_p;
	struct rsbac_list_lol_item_t *current_p;
	struct rsbac_list_item_t *sub_p;
        struct rsbac_list_buffer_t *buffer = NULL;
        rsbac_list_count_t allcount = 0;
	rsbac_version_t list_version = RSBAC_LIST_DISK_VERSION;
	rsbac_time_t timestamp = RSBAC_CURRENT_TIME;
	int i;
	const u_int nr_hashes = BIT(list->hash_bits);

	write_item_p = rsbac_kmalloc_unlocked(sizeof(*write_item_p));
	if (unlikely(!write_item_p)) {
		*write_item_pp = NULL;
		return (-RSBAC_ENOMEM);
	}

	rsbac_pr_debug(write, "Filling buffers for list of lists %s\n",
		       list->name);
	/* fill write_item */
	write_item_p->prev = NULL;
	write_item_p->next = NULL;
	write_item_p->list = list;
	write_item_p->buffer = NULL;
	strncpy(write_item_p->name, list->name, RSBAC_LIST_MAX_FILENAME);
	write_item_p->name[RSBAC_LIST_MAX_FILENAME] = 0;
	write_item_p->major = list->major;
	write_item_p->minor = list->minor;

	buffer = rsbac_kmalloc(sizeof(*buffer));
	if (unlikely(!buffer)) {
		rsbac_kfree(write_item_p);
		*write_item_pp = NULL;
		return -RSBAC_ENOMEM;
	}
	buffer->data = rsbac_kmalloc(RSBAC_LIST_BUFFER_SIZE);
	if (unlikely(!buffer->data)) {
		rsbac_kfree(buffer);
		rsbac_kfree(write_item_p);
		*write_item_pp = NULL;
		return -RSBAC_ENOMEM;
	}
	write_item_p->buffer = buffer;
	buffer->len = 0;
	buffer->next = NULL;
	/* copy version */
	memcpy(buffer->data, (char *) &list_version, sizeof(list_version));
	buffer->len = sizeof(list_version);
	/* copy timestamp */
	memcpy(buffer->data + buffer->len,
	       (char *) &timestamp, sizeof(timestamp));
	buffer->len += sizeof(timestamp);
	/* copy info */
	memcpy(buffer->data + buffer->len,
	       (char *) &list->info, sizeof(list->info));
	buffer->len += sizeof(list->info);
	/* protect list */
	rcu_read_lock();
	for (i=0; i<nr_hashes; i++)
		allcount += list->hashed[i].count;
	/* copy lastchange */
	memcpy(buffer->data + buffer->len,
	       (char *) &list->lastchange, sizeof(list->lastchange));
	buffer->len += sizeof(list->lastchange);
	/* copy count */
	memcpy(buffer->data + buffer->len,
	       (char *) &allcount, sizeof(allcount));
	buffer->len += sizeof(allcount);
	/* copy list */
	for (i=0; i<nr_hashes; i++) {
		current_p = list->hashed[i].head;
		while (current_p) {
			if (unlikely(check_buffer(&buffer, sizeof(current_p->max_age)
				 + list->info.desc_size
				 + list->info.data_size
				 + sizeof(current_p->count)))) {
				/* unprotect this list */
				rcu_read_unlock();
				free_buffers(write_item_p->buffer);
				rsbac_kfree(write_item_p);
				*write_item_pp = NULL;
				return -RSBAC_ENOMEM;
			}
			memcpy(buffer->data + buffer->len,
			       &current_p->max_age, sizeof(current_p->max_age));
			buffer->len += sizeof(current_p->max_age);
			memcpy(buffer->data + buffer->len,
			       ((char *) current_p) + sizeof(*current_p),
			       list->info.desc_size + list->info.data_size);
			buffer->len += list->info.desc_size + list->info.data_size;
			memcpy(buffer->data + buffer->len,
			       &current_p->count, sizeof(current_p->count));
			buffer->len += sizeof(current_p->count);
			/* copy subitems */
			sub_p = current_p->head;
			while (sub_p) {
				if (unlikely(check_buffer(&buffer, sizeof(sub_p->max_age)
					 + list->info.subdesc_size
					 + list->info.subdata_size))) {
					/* unprotect this list */
					rcu_read_unlock();
					free_buffers(write_item_p->buffer);
					rsbac_kfree(write_item_p);
					*write_item_pp = NULL;
					return -RSBAC_ENOMEM;
				}
				memcpy(buffer->data + buffer->len,
				       &sub_p->max_age, sizeof(sub_p->max_age));
				buffer->len += sizeof(sub_p->max_age);
				memcpy(buffer->data + buffer->len,
				       ((char *) sub_p) + sizeof(*sub_p),
				       list->info.subdesc_size +
				       list->info.subdata_size);
				buffer->len +=
				    list->info.subdesc_size +
				    list->info.subdata_size;
				sub_p = sub_p->next;
			}
			current_p = current_p->next;
		}
	}
	/* unprotect this list */
	rcu_read_unlock();
	*write_item_pp = write_item_p;

	return 0;
}

/* call unlocked */
static int rsbac_list_write_lol_buffers(struct rsbac_list_lol_write_head_t
					write_head)
{
	long file_fd;
	int count = 0;
	u_long written;
        u_long all_written;
	u_long bytes;
        u_int bufcount;
	int tmperr = 0;
        struct rsbac_list_buffer_t * buffer;
	struct rsbac_list_lol_write_item_t *write_item_p;
	struct rsbac_list_lol_write_item_t *next_item_p;

	write_item_p = write_head.head;
	while (write_item_p) {
		rsbac_pr_debug(write, "write list of lists %s on device %02u:%02u.\n",
			       write_item_p->name,
			       write_item_p->major, write_item_p->minor);
		/* open file */
		if ((file_fd = rsbac_write_open(write_item_p->name,
					        write_item_p->major, write_item_p->minor)) < 0) {
			if (file_fd != -RSBAC_ENOTWRITABLE) {
				rsbac_printk(KERN_WARNING "rsbac_list_write_lol_buffers(): opening file %s on device %02u:%02u failed with error %i!\n",
					     write_item_p->name,
					     write_item_p->major, write_item_p->minor,
					     file_fd);
			}
			count = file_fd;
			goto out_free_all;
		}

		buffer = write_item_p->buffer;
		all_written = 0;
		bufcount = 0;
		while (buffer && (tmperr >= 0)) {
			rsbac_pr_debug(write, "Writing list of lists %s, buffer %u with size %u\n",
					write_item_p->name, bufcount, buffer->len);
			bufcount++;
			written = 0;
			while ((written < buffer->len) && (tmperr >= 0)) {
				bytes = buffer->len - written;
				tmperr = rsbac_write_file(file_fd,
							buffer->data + written,
							bytes);
				if (tmperr > 0) {
					written += tmperr;
				}
			}
			all_written += written;
			buffer = buffer->next;
		}
		/* End of write access */
		rsbac_write_close(file_fd);

		if (tmperr < 0) {
			rsbac_printk(KERN_WARNING "rsbac_list_write_lol_buffers(): write error %i on device %02u:%02u file %s!\n",
				     tmperr,
				     write_item_p->major, write_item_p->minor,
				     write_item_p->name);
			count = tmperr;
			goto out_free_all;
		} else
			count++;

		rsbac_pr_debug(write, "%lu bytes from %u buffers written.\n",
			       all_written, bufcount);
                free_buffers(write_item_p->buffer);
		next_item_p = write_item_p->next;
		rsbac_kfree(write_item_p);
		write_item_p = next_item_p;
	}
	return count;

out_free_all:
    /* Mark unwritten lists dirty and free everything */
    while(write_item_p)
      {
        if(write_item_p->list->self == write_item_p->list)
          write_item_p->list->dirty = TRUE;
	free_buffers(write_item_p->buffer);
        next_item_p = write_item_p->next;
        rsbac_kfree(write_item_p);
        write_item_p = next_item_p;
      }
    return count;
}
#endif				/* ifndef CONFIG_RSBAC_NO_WRITE */

/************************************************* */
/*           PROC support                          */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
lists_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	struct rsbac_list_reg_item_t *item_p;
	struct rsbac_list_lol_reg_item_t *lol_item_p;
	int i;
	u_long tmp_count;
	int srcu_idx;
	struct rsbac_list_hashed_t * hashed;
	struct rsbac_list_lol_hashed_t * lol_hashed;
	u_int nr_hashes;

	if (unlikely(!rsbac_is_initialized()))
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
		    "Generic Lists Status\n--------------------\nMaximum number of hash bits per list/list of lists is %u\nrsbac_list_auto_rehash_trigger is %u\n%u list read failures\n",
		    rsbac_list_max_hash_bits, rsbac_list_auto_rehash_trigger, rsbac_list_read_errors);
#ifdef CONFIG_RSBAC_RC_LEARN_TA
	seq_printf(m, "RC   Learning Mode transaction Number: %u\n",
		CONFIG_RSBAC_RC_LEARN_TA);
#endif
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
	seq_printf(m, "AUTH Learning Mode transaction Number: %u\n",
		CONFIG_RSBAC_AUTH_LEARN_TA);
#endif
#ifdef CONFIG_RSBAC_ACL_LEARN_TA
	seq_printf(m, "ACL  Learning Mode transaction Number: %u\n",
		CONFIG_RSBAC_ACL_LEARN_TA);
#endif
#ifdef CONFIG_RSBAC_CAP_LEARN_TA
	seq_printf(m, "CAP  Learning Mode transaction Number: %u\n",
		CONFIG_RSBAC_CAP_LEARN_TA);
#endif
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (rsbac_list_count(ta_handle) > 0) {
		int list_count;
		rsbac_list_ta_number_t *desc_array;
		struct rsbac_list_ta_data_t data;

		seq_printf(m, "\nTransactions active:\n\n");
		list_count =
		    rsbac_list_get_all_desc(ta_handle,
					    (void **) &desc_array);
		if (list_count > 0) {
			int i;
			rsbac_time_t now = RSBAC_CURRENT_TIME;

			for (i = 0; i < list_count; i++) {
				if (!rsbac_list_get_data
				    (ta_handle, &desc_array[i], &data)) {
					seq_printf(m,
						    "%u %s (ttl %is)\n",
						    desc_array[i],
						    data.name,
						    data.timeout - now);
				}
			}
			rsbac_kfree(desc_array);
		}

		seq_printf(m,
			    "\nLists in Transaction\n--------------------\nName\t\tdevice\thash\tta\t     count\n");

		list_count = 0;
		srcu_idx = srcu_read_lock(&reg_list_srcu);
		item_p = srcu_dereference(reg_head.head, &reg_list_srcu);
		while (item_p) {
			rcu_read_lock();
			nr_hashes = BIT(item_p->hash_bits);
			hashed = rcu_dereference(item_p->hashed);
			for (i=0; i<nr_hashes; i++) {
				if (hashed[i].ta_copied) {
					seq_printf(m,
						    "%-16s%02u:%02u\t%u\t%10u\t%u\n",
						    item_p->name,
						    item_p->major, item_p->minor,
						    i,
						    hashed[i].ta_copied,
						    hashed[i].ta_count);
					list_count++;
				}
			}
			rcu_read_unlock();
			item_p = srcu_dereference(item_p->next, &reg_list_srcu);
		}
		srcu_read_unlock(&reg_list_srcu, srcu_idx);

		seq_printf(m,
			    "\n %u lists in transaction.\n\n", list_count);
		seq_printf(m,
			    "Lists of Lists in Transaction\n-----------------------------\nName\t\tdevice\thash\tta\t     count\n");
		list_count = 0;
		srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
		lol_item_p = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
		while (lol_item_p) {
			rcu_read_lock();
			nr_hashes = BIT(lol_item_p->hash_bits);
			lol_hashed = rcu_dereference(lol_item_p->hashed);
			for (i=0; i<nr_hashes; i++) {
				if (lol_hashed[i].ta_copied) {
					seq_printf(m,
						    "%-16s%02u:%02u\t%u\t%10u\t%u\n",
						    lol_item_p->name,
						    lol_item_p->major, lol_item_p->minor,
						    i,
						    lol_hashed[i].ta_copied,
						    lol_hashed[i].ta_count);
					list_count++;
				}
			}
			rcu_read_unlock();
			lol_item_p = srcu_dereference(lol_item_p->next, &lol_reg_list_srcu);
		}
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);

		seq_printf(m,
			    "\n %u lists of lists in transaction.\n\n",
			    list_count);
	} else
		seq_printf(m, "No active transaction\n");
#endif
	seq_printf(m,
		    "\nRegistered Generic Lists (item size %u + per hash %u)\n------------------------\n",
		    (int) sizeof(struct rsbac_list_reg_item_t), (int) sizeof(struct rsbac_list_hashed_t));
	seq_printf(m,
		    "Name\t\tdevice\tcount\tdesc\tdata\tpersist\tnow/dir\tflags\thashbits\n");

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	item_p = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (item_p) {
		rcu_read_lock();
		nr_hashes = BIT(item_p->hash_bits);
		hashed = rcu_dereference(item_p->hashed);
		tmp_count = 0;
		for (i=0; i<nr_hashes; i++)
			tmp_count += hashed[i].count;
		rcu_read_unlock();
		seq_printf(m,
			    "%-16s%02u:%02u\t%lu\t%u\t%u\t%u\t%u/%u\t%u\t%u\n",
			    item_p->name, item_p->major, item_p->minor, tmp_count,
			    item_p->info.desc_size, item_p->info.data_size,
			    item_p->flags & RSBAC_LIST_PERSIST,
			    item_p->no_write,
			    item_p->dirty & (item_p->
					     flags & RSBAC_LIST_PERSIST),
			    item_p->flags,
			    item_p->hash_bits);
		item_p = srcu_dereference(item_p->next, &reg_list_srcu);
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);

	seq_printf(m, "\n %u lists registered.\n\n",
		       reg_head.count);
	seq_printf(m,
		    "Registered Generic Lists of Lists (item size %u + per hash %u)\n---------------------------------\n",
		    (int) sizeof(struct rsbac_list_lol_reg_item_t), (int) sizeof(struct rsbac_list_lol_hashed_t));
	seq_printf(m,
		    "Name\t\tdevice\tcount\tdesc\tdata\tpersist\tnow/dir\tflags\thashbits\n");

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	lol_item_p = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_item_p) {
		rcu_read_lock();
		nr_hashes = BIT(lol_item_p->hash_bits);
		lol_hashed = rcu_dereference(lol_item_p->hashed);
		tmp_count = 0;
		for (i=0; i<nr_hashes; i++)
			tmp_count += lol_hashed[i].count;
		rcu_read_unlock();
		seq_printf(m,
			    "%-16s%02u:%02u\t%lu\t%u+%u\t%u+%u\t%u\t%u/%u\t%u\t%u\n",
			    lol_item_p->name,
			    lol_item_p->major, lol_item_p->minor,
			    tmp_count, lol_item_p->info.desc_size,
			    lol_item_p->info.subdesc_size,
			    lol_item_p->info.data_size,
			    lol_item_p->info.subdata_size,
			    lol_item_p->flags & RSBAC_LIST_PERSIST,
			    lol_item_p->no_write,
			    lol_item_p->dirty & (lol_item_p->
						 flags &
						 RSBAC_LIST_PERSIST),
			    lol_item_p->flags,
			    lol_item_p->hash_bits);
		lol_item_p = srcu_dereference(lol_item_p->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);

	seq_printf(m, "\n %u lists of lists registered.\n",
		       lol_reg_head.count);
	return 0;
}

static int lists_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lists_proc_show, NULL);
}

static const struct proc_ops lists_proc_ops = {
       .proc_open           = lists_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *lists_proc;

static int
lists_counts_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	struct rsbac_list_reg_item_t *item_p;
	struct rsbac_list_lol_reg_item_t *lol_item_p;
	int i;
#ifdef CONFIG_RSBAC_LIST_STATS
	__u64 all_read = 0;
	__u64 all_write = 0;
#endif
	int srcu_idx;
	struct rsbac_list_hashed_t * hashed;
	struct rsbac_list_lol_hashed_t * lol_hashed;
	u_int nr_hashes;
	u_long subcount;
	struct rsbac_list_lol_item_t *sublist;

	if (unlikely(!rsbac_is_initialized()))
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
		    "Generic Lists Status\n--------------------\nMaximum number of hash bits per list/list of lists is %u\n\n",
		    rsbac_list_max_hash_bits);
	seq_printf(m,
		    "Registered Generic Lists (item size %u + per hash %u)\n------------------------\n",
		    (int) sizeof(struct rsbac_list_reg_item_t), (int) sizeof(struct rsbac_list_hashed_t));
#ifdef CONFIG_RSBAC_LIST_STATS
	seq_printf(m,
		    "Name\t\tdevice\tmaxitem\treads\twrites\thashbit\tcounts\n");
#else
	seq_printf(m,
		    "Name\t\tdevice\tmaxitem\thashbit\tcounts\n");
#endif
	srcu_idx = srcu_read_lock(&reg_list_srcu);
	item_p = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (item_p) {
#ifdef CONFIG_RSBAC_LIST_STATS
		seq_printf(m,
			    "%-16s%02u:%02u\t%u\t%llu\t%llu\t%u\t",
			    item_p->name, item_p->major, item_p->minor,
			    item_p->max_items_per_hash,
			    item_p->read_count,
			    item_p->write_count,
			    item_p->hash_bits);
		all_read += item_p->read_count;
		all_write += item_p->write_count;
#else
		seq_printf(m,
			    "%-16s%02u:%02u\t%u\t%u\t",
			    item_p->name,
			    item_p->major, item_p->minor,
			    item_p->max_items_per_hash,
			    item_p->hash_bits);
#endif
		rcu_read_lock();
		nr_hashes = BIT(item_p->hash_bits);
		hashed = rcu_dereference(item_p->hashed);
		for (i=0; i<nr_hashes; i++) {
			seq_printf(m,
				    "%u ",
				    hashed[i].count);
		}
		rcu_read_unlock();
		seq_printf(m,
			    "\n");
		item_p = srcu_dereference(item_p->next, &reg_list_srcu);
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);

#ifdef CONFIG_RSBAC_LIST_STATS
	seq_printf(m, "\n %u lists registered, %llu reads, %llu writes\n\n",
		       reg_head.count, all_read, all_write);
	all_read = 0;
	all_write = 0;
#else
	seq_printf(m, "\n %u lists registered.\n\n",
		       reg_head.count);
#endif
	seq_printf(m,
		    "Registered Generic Lists of Lists (item size %u + per hash %u)\n---------------------------------\n",
		    (int) sizeof(struct rsbac_list_lol_reg_item_t), (int) sizeof(struct rsbac_list_lol_hashed_t));
#ifdef CONFIG_RSBAC_LIST_STATS
	seq_printf(m,
		    "Name\t\tdevice\tmaxitem\tmaxsubi\treads\twrites\thashbit\tcounts(sub)\n");
#else
	seq_printf(m,
		    "Name\t\tdevice\tmaxitem\tmaxsubi\thashbit\tcounts(sub)\n");
#endif
	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	lol_item_p = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_item_p) {
#ifdef CONFIG_RSBAC_LIST_STATS
		seq_printf(m,
			    "%-16s%02u:%02u\t%u\t%u\t%llu\t%llu\t%u\t",
			    lol_item_p->name,
			    lol_item_p->major, lol_item_p->minor,
			    lol_item_p->max_items_per_hash,
			    lol_item_p->max_subitems,
			    lol_item_p->read_count,
			    lol_item_p->write_count,
			    lol_item_p->hash_bits);
		all_read += lol_item_p->read_count;
		all_write += lol_item_p->write_count;
#else
		seq_printf(m,
			    "%-16s%02u:%02u\t%u\t%u\t%u\t",
			    lol_item_p->name,
			    lol_item_p->major, lol_item_p->minor,
			    lol_item_p->max_items_per_hash,
			    lol_item_p->max_subitems,
			    lol_item_p->hash_bits);
#endif
		rcu_read_lock();
		nr_hashes = BIT(lol_item_p->hash_bits);
		lol_hashed = rcu_dereference(lol_item_p->hashed);
		for (i=0; i<nr_hashes; i++) {
			subcount = 0;

			sublist = rcu_dereference(lol_hashed[i].head);
			while (sublist) {
				subcount += sublist->count;
				sublist = rcu_dereference(sublist->next);
			}
			seq_printf(m,
				    "%u(%lu) ",
				    lol_hashed[i].count,
				    subcount);
		}
		rcu_read_unlock();
		seq_printf(m,
			    "\n");
		lol_item_p = srcu_dereference(lol_item_p->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);

#ifdef CONFIG_RSBAC_LIST_STATS
	seq_printf(m, "\n %u lists of lists registered, %llu reads, %llu writes\n\nRCU Garbage Collector call statistics\n-------------------------------------\n",
		       lol_reg_head.count, all_read, all_write);
	seq_printf(m, "rcu_free:                   %llu\n", rcu_free_calls);
	seq_printf(m, "rcu_free_item_chain:        %llu\n", rcu_free_item_chain_calls);
	seq_printf(m, "rcu_free_lol:               %llu\n", rcu_free_lol_calls);
	seq_printf(m, "rcu_free_lol_sub:           %llu\n", rcu_free_lol_sub_calls);
	seq_printf(m, "rcu_free_lol_item_chain:    %llu\n", rcu_free_lol_item_chain_calls);
	seq_printf(m, "rcu_free_lol_subitem_chain: %llu\n", rcu_free_lol_subitem_chain_calls);
	seq_printf(m, "rcu_free_do_cleanup:        %llu\n", rcu_free_do_cleanup_calls);
	seq_printf(m, "rcu_free_do_cleanup_lol:    %llu\n", rcu_free_do_cleanup_lol_calls);
	seq_printf(m, "rcu_free_callback:          %llu\n", rcu_free_callback_calls);
	seq_printf(m, "rcu_free_callback_lol:      %llu\n", rcu_free_callback_lol_calls);
	seq_printf(m, "rcu_free_alloc_failed:      %llu\n", rcu_free_alloc_failed);
	seq_printf(m, "rcu_free_lol_alloc_failed:  %llu\n", rcu_free_lol_alloc_failed);
	seq_printf(m, "rcu_free_lol_sub_alloc_failed: %llu\n", rcu_free_lol_sub_alloc_failed);
	seq_printf(m, "rcu_callback_count:         %u\n", rcu_callback_count);
	seq_printf(m, "max_rcu_callback_count:     %u\n", max_rcu_callback_count);
	seq_printf(m, "rcu_rate:                   %u/s\n", rsbac_list_rcu_rate);
	seq_printf(m, "rcu_rate_reached_count:     %llu\n", rcu_rate_reached_count);
#ifndef CONFIG_TINY_RCU
	seq_printf(m, "system RCU total completed: %lu\n", rcu_exp_batches_completed());
#endif
#else
	seq_printf(m, "\n %u lists of lists registered.\n",
		       lol_reg_head.count);
#endif
	return 0;
}

static int lists_counts_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lists_counts_proc_show, NULL);
}

static const struct proc_ops lists_counts_proc_ops = {
       .proc_open           = lists_counts_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static struct proc_dir_entry *lists_counts_proc;

/* Generic backup generation function */
static int backup_proc_show(struct seq_file *m, void *data)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *current_p;
	rsbac_version_t list_version = RSBAC_LIST_DISK_VERSION;
	rsbac_time_t timestamp = RSBAC_CURRENT_TIME;
	int srcu_idx;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;
	int i;

	if (unlikely(!rsbac_is_initialized()))
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

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	list = lookup_reg(data);
	if (unlikely(!list)) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		return -ENOSYS;
	}
	/* copy version */
	seq_write(m, &list_version, sizeof(list_version));
	/* copy version */
	seq_write(m, &timestamp, sizeof(timestamp));
	/* copy info */
	seq_write(m, &list->info, sizeof(list->info));

	rcu_read_lock();
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	/* copy list */
	for (i=0; i<nr_hashes; i++) {
		current_p = rcu_dereference(hashed[i].head);
		while (current_p) {
			seq_write(m,
			       ((char *) current_p) + sizeof(*current_p),
			       list->info.desc_size + list->info.data_size);
			current_p = rcu_dereference(current_p->next);
		}
	}

	rcu_read_unlock();
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	return 0;
}

/* Generic lists of lists backup generation function */
static int lol_backup_proc_show(struct seq_file *m, void *data)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *current_p;
	struct rsbac_list_item_t *sub_p;
	rsbac_version_t list_version = RSBAC_LIST_DISK_VERSION;
	rsbac_time_t timestamp = RSBAC_CURRENT_TIME;
	int srcu_idx;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;
	int i;

	if (unlikely(!rsbac_is_initialized()))
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

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	list = lookup_lol_reg(data);
	if (unlikely(!list)) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		return -ENOSYS;
	}
	/* copy version */
	seq_write(m, &list_version, sizeof(list_version));
	/* copy version */
	seq_write(m, &timestamp, sizeof(timestamp));
	/* copy info */
	seq_write(m, &list->info, sizeof(list->info));

	rcu_read_lock();
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	/* copy list */
	for (i=0; i<nr_hashes; i++) {
		current_p = rcu_dereference(hashed[i].head);
		while (current_p) {
			seq_write(m,
			       ((char *) current_p) + sizeof(*current_p),
			       list->info.desc_size + list->info.data_size);
			seq_write(m,
			       &current_p->count, sizeof(current_p->count));
			/* copy sublist */
			sub_p = rcu_dereference(current_p->head);
	 		while (sub_p) {
				seq_write(m,
				       ((char *) sub_p) + sizeof(*sub_p),
				       list->info.subdesc_size +
				       list->info.subdata_size);
				sub_p = rcu_dereference(sub_p->next);
			}
			current_p = rcu_dereference(current_p->next);
		}
	}
	rcu_read_unlock();
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	return 0;
}
#endif				/* PROC */


/********************/
/* Init and general */
/********************/
int rsbac_list_compare_u32(void * desc1, void * desc2)
  {
    if( *((__u32*) desc1) < *((__u32*) desc2))
      return -1;
    return( *((__u32*) desc1) != *((__u32*) desc2));
  }

static void rcu_rate_reset(struct timer_list * dummy)
{
#ifdef CONFIG_RSBAC_DEBUG
	if (rcu_callback_count > rsbac_list_rcu_rate) {
		rsbac_pr_debug(lists,
				"rcu_callback_count %u over rcu_rate %u, list write accesses have been throttled\n",
				rcu_callback_count, rsbac_list_rcu_rate);
	}
#endif
#ifdef CONFIG_RSBAC_LIST_STATS
	if (rcu_callback_count > max_rcu_callback_count)
		max_rcu_callback_count = rcu_callback_count;
#endif
	rcu_callback_count = 0;

	mod_timer(&rcu_rate_timer, jiffies + HZ);
}

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_list_init(void)
#else
int __init rsbac_list_init(void)
#endif
{
#if defined(CONFIG_RSBAC_LIST_TRANS) || defined(CONFIG_RSBAC_LIST_REPL)
	int err;
	struct rsbac_list_info_t *list_info_p;
#endif
	reg_item_slab = rsbac_slab_create_rcu("rsbac_reg_item",
					sizeof(struct rsbac_list_reg_item_t));
	lol_reg_item_slab = rsbac_slab_create_rcu("rsbac_lol_reg_item",
					sizeof(struct rsbac_list_lol_reg_item_t));
	rcu_free_item_slab = rsbac_slab_create("rsbac_rcu_free_item",
					sizeof(struct rsbac_list_rcu_free_item_t));
	rcu_free_head_slab = rsbac_slab_create("rsbac_rcu_free_head",
					sizeof(struct rsbac_list_rcu_free_head_t));
	rcu_free_head_lol_slab = rsbac_slab_create("rsbac_rcu_free_head_lol",
					sizeof(struct rsbac_list_rcu_free_head_lol_t));

	reg_head.head = NULL;
	reg_head.tail = NULL;
	reg_head.curr = NULL;
	spin_lock_init(&reg_head.lock);
	init_srcu_struct(&reg_list_srcu);
	init_srcu_struct(&lol_reg_list_srcu);
	reg_head.count = 0;

	lol_reg_head.head = NULL;
	lol_reg_head.tail = NULL;
	lol_reg_head.curr = NULL;
	spin_lock_init(&lol_reg_head.lock);
	lol_reg_head.count = 0;

	if(CONFIG_RSBAC_LIST_MAX_HASH_BITS < RSBAC_LIST_MIN_MAX_HASH_BITS)
		rsbac_list_max_hash_bits = RSBAC_LIST_MIN_MAX_HASH_BITS;
	else if (CONFIG_RSBAC_LIST_MAX_HASH_BITS > RSBAC_LIST_MAX_MAX_HASH_BITS)
		rsbac_list_max_hash_bits = RSBAC_LIST_MAX_MAX_HASH_BITS;
	else
		rsbac_list_max_hash_bits = CONFIG_RSBAC_LIST_MAX_HASH_BITS;

	list_initialized = TRUE;

#if defined(CONFIG_RSBAC_LIST_TRANS) || defined(CONFIG_RSBAC_LIST_REPL)
	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (unlikely(!list_info_p)) {
		return -ENOMEM;
	}
#endif

	/* init proc entry */
#if defined(CONFIG_RSBAC_PROC)
	{
		lists_proc = proc_create(RSBAC_LIST_PROC_NAME, S_IFREG | S_IRUGO,
				proc_rsbac_root_p, &lists_proc_ops);
		lists_counts_proc = proc_create(RSBAC_LIST_COUNTS_PROC_NAME,
						S_IFREG | S_IRUGO,
						proc_rsbac_root_p,
						&lists_counts_proc_ops);
	}
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
	rsbac_printk(KERN_INFO "rsbac_list_init(): Registering transaction list.\n");
	list_info_p->version = 1;
	list_info_p->key = RSBAC_LIST_TA_KEY;
	list_info_p->desc_size = sizeof(rsbac_list_ta_number_t);
	list_info_p->data_size = sizeof(struct rsbac_list_ta_data_t);
	list_info_p->max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  (void **) &ta_handle,
				  list_info_p,
				  0,
				  NULL,
				  NULL,
				  NULL, "transactions", RSBAC_AUTO_DEV_NUM, RSBAC_AUTO_DEV_NUM);
	if (err) {
		char *tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_list_init(): Registering transaction list failed with error %s\n",
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
#endif

#if defined(CONFIG_RSBAC_LIST_TRANS) || defined(CONFIG_RSBAC_LIST_REPL)
	rsbac_kfree(list_info_p);
#endif

	timer_setup(&rcu_rate_timer, rcu_rate_reset, 0);
	rcu_rate_timer.expires = jiffies + HZ;
	add_timer(&rcu_rate_timer);
	return 0;
}

#ifdef CONFIG_RSBAC_AUTO_WRITE
static int rsbac_list_auto_rehash(rsbac_boolean_t force_rehash);

int rsbac_write_lists()
{
	int count = 0;
	int subcount = 0;
	int error = 0;
	struct rsbac_list_reg_item_t *item_p;
	struct rsbac_list_lol_reg_item_t *lol_item_p;
	struct rsbac_list_write_head_t write_head;
	struct rsbac_list_write_item_t *write_item_p;
	struct rsbac_list_lol_write_head_t write_lol_head;
	struct rsbac_list_lol_write_item_t *write_lol_item_p;
	int srcu_idx;

/*
	rsbac_pr_debug(lists, "called.\n");
*/
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

#ifdef CONFIG_RSBAC_LIST_TRANS
	if (rsbac_list_count(ta_handle) > 0) {
		int list_count;
		rsbac_list_ta_number_t *desc_array;
		struct rsbac_list_ta_data_t data;

		list_count =
		    rsbac_list_get_all_desc(ta_handle,
					    (void **) &desc_array);
		if (list_count > 0) {
			int i;
			rsbac_time_t now = RSBAC_CURRENT_TIME;

			for (i = 0; i < list_count; i++) {
				if (!rsbac_list_get_data
				    (ta_handle, &desc_array[i], &data)) {
					if (data.timeout < now) {
						rsbac_printk(KERN_WARNING "rsbac_write_lists(): transaction %u timed out, forcing forget\n",
							     desc_array
							     [i]);
						do_forget(desc_array[i]);
					}
				}
			}
			rsbac_kfree(desc_array);
		}
	}
#endif

	/* Init buffer list */
	write_head.head = NULL;
	write_head.tail = NULL;
	write_head.count = 0;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	item_p = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (item_p) {
		if ((item_p->flags & RSBAC_LIST_PERSIST)
		    && item_p->dirty && !item_p->no_write
		    && !rsbac_debug_no_write) {
		    	struct vfsmount *mnt_p;

			mnt_p = rsbac_get_vfsmount(item_p->major, item_p->minor);
			if (mnt_p && rsbac_writable(mnt_p->mnt_sb)) {
				item_p->dirty = FALSE;
				error = fill_buffer(item_p, &write_item_p);
				if (!error) {
					if (!write_head.head) {
						write_head.head = write_item_p;
						write_head.tail = write_item_p;
						write_head.count = 1;
					} else {
						write_head.tail->next =
						    write_item_p;
						write_item_p->prev =
						    write_head.tail;
						write_head.tail = write_item_p;
						write_head.count++;
					}
				} else {
					if ((error != -RSBAC_ENOTWRITABLE)
					    && (error != -RSBAC_ENOMEM)
					    ) {
						rsbac_printk(KERN_WARNING "rsbac_write_lists(): fill_buffer() for list %s returned error %i\n",
							     item_p->name, error);
					item_p->dirty = TRUE;
					}
				}
			}
		}
		item_p = srcu_dereference(item_p->next, &reg_list_srcu);
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);

	if (write_head.count > 0)
		rsbac_pr_debug(write, "%u lists copied to buffers\n",
			       write_head.count);

	/* write all buffers */
	if (write_head.count) {
		count = rsbac_list_write_buffers(write_head);
		rsbac_pr_debug(write, "%u lists written to disk\n", count);
	}

	/* LOL */
	/* Init buffer list */
	write_lol_head.head = NULL;
	write_lol_head.tail = NULL;
	write_lol_head.count = 0;

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	lol_item_p = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_item_p) {
		if ((lol_item_p->flags & RSBAC_LIST_PERSIST)
		    && lol_item_p->dirty && !lol_item_p->no_write
		    && !rsbac_debug_no_write) {
		    	struct vfsmount *mnt_p;

			mnt_p = rsbac_get_vfsmount(lol_item_p->major, lol_item_p->minor);
			if (mnt_p && rsbac_writable(mnt_p->mnt_sb)) {
				lol_item_p->dirty = FALSE;
				error = fill_lol_buffer(lol_item_p, &write_lol_item_p);
				if (!error) {
					if (!write_lol_head.head) {
						write_lol_head.head =
							    write_lol_item_p;
						write_lol_head.tail =
						    write_lol_item_p;
						write_lol_head.count = 1;
					} else {
						write_lol_head.tail->next =
						    write_lol_item_p;
						write_lol_item_p->prev =
						    write_lol_head.tail;
						write_lol_head.tail =
						    write_lol_item_p;
						write_lol_head.count++;
					}
				} else {
					if ((error != -RSBAC_ENOTWRITABLE)
					    && (error != -RSBAC_ENOMEM))
					    {
						rsbac_printk(KERN_WARNING "rsbac_write_lists(): fill_lol_buffer() for list %s returned error %i\n",
							     lol_item_p->name,
							     error);
					}
					lol_item_p->dirty = TRUE;
				}
			}
		}
		lol_item_p = srcu_dereference(lol_item_p->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);

	if (write_lol_head.count > 0)
		rsbac_pr_debug(write, "%u lists of lists copied to buffers\n",
			       write_lol_head.count);
	/* write all buffers */
	if (write_lol_head.count) {
		subcount =
		    rsbac_list_write_lol_buffers(write_lol_head);
		count += subcount;
		rsbac_pr_debug(write, "%u lists of lists written to disk\n",
			       subcount);
	}
	rsbac_pr_debug(write, "%u lists written.\n",
		       count);

	return count;
}

void rsbac_rehash_lists(rsbac_boolean_t force_rehash)
{
	if(force_rehash || (jiffies > next_rehash)) {
		rsbac_list_auto_rehash(force_rehash);
		next_rehash = jiffies + (RSBAC_LIST_REHASH_INTERVAL * HZ);
	}
}
#endif				/* CONFIG_RSBAC_AUTO_WRITE */

/* Status checking */
int rsbac_check_lists(const int correct)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_lol_reg_item_t *lol_list;
	struct rsbac_list_item_t *item_p;
	struct rsbac_list_item_t *next_item_p;
	struct rsbac_list_lol_item_t *lol_item_p;
	struct rsbac_list_lol_item_t *next_lol_item_p;
	struct rsbac_list_item_t *lol_subitem_p;
	struct rsbac_list_item_t *next_lol_subitem_p;
	u_long tmp_count;
	u_long tmp_subcount;
	u_long subitem_count;
	u_long dirty = 0;
	u_int remove_count;
	int i;
	u_long all_count;
	struct rsbac_list_rcu_free_head_t ** rcu_head_pp = NULL;
	struct rsbac_list_rcu_free_head_lol_t ** rcu_head_lol_pp = NULL;
	int srcu_idx;
	u_int nr_hashes;

	rsbac_pr_debug(lists, "called.\n");
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	srcu_idx = srcu_read_lock(&reg_list_srcu);
	list = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (list) {
restart:
		if(list->hash_function)
			read_lock(&list->hash_lock);
		nr_hashes = BIT(list->hash_bits);
		rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_pp));
		if (unlikely(!rcu_head_pp)) {
			if(list->hash_function)
				read_unlock(&list->hash_lock);
			srcu_read_unlock(&reg_list_srcu, srcu_idx);
			return -RSBAC_ENOMEM;
		}
		remove_count = 0;
		/* check list */
		all_count = 0;
		for (i=0; i<nr_hashes; i++) {
			tmp_count = 0;
			spin_lock(&list->hashed[i].lock);
			item_p = list->hashed[i].head;
			while (item_p) {
				if ((item_p->max_age
				     && (item_p->max_age <= RSBAC_CURRENT_TIME)
				    )
				    || (list->def_data
					&& !memcmp(((char *) item_p) +
						   sizeof(*item_p) +
						   list->info.desc_size,
						   list->def_data,
						   list->info.data_size)
				    )
				    ) {
					next_item_p = item_p->next;
					do_remove_item(list, item_p, i);
					remove_count++;
					if (remove_count > rsbac_list_rcu_rate) {
						rcu_head_pp[i] = get_rcu_free(list, i);
						spin_unlock(&list->hashed[i].lock);
						if(list->hash_function)
							read_unlock(&list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
						rcu_rate_reached_count++;
#endif
						synchronize_rcu();
						for (i=0; i<nr_hashes; i++)
							rcu_free_do_cleanup(rcu_head_pp[i]);
						rsbac_kfree(rcu_head_pp);
						goto restart;
					}
					item_p = next_item_p;
				} else {
					tmp_count++;
					if (tmp_count > (2 * list->max_items_per_hash)) {
						tmp_count = 0;
						rsbac_printk(KERN_WARNING "rsbac_check_lists(): list %s hash %u on device %02u:%02u counts an invalid number %lu of items, should be %u, skipping further checks!\n",
							     list->name, i,
							     list->major, list->minor,
							     tmp_count, list->hashed[i].count);
					}
					item_p = item_p->next;
				}
			}
			if ((tmp_count > 0) && (tmp_count != list->hashed[i].count)) {
				if (correct) {
					rsbac_printk(KERN_WARNING "rsbac_check_lists(): correcting count mismatch for list %s hash %u on device %02u:%02u - was %u, counted %lu!\n",
						     list->name, i,
						     list->major, list->minor,
						     list->hashed[i].count, tmp_count);
					list->hashed[i].count = tmp_count;
				} else {
					rsbac_printk(KERN_WARNING "rsbac_check_lists(): count mismatch for list %s hash %u on device %02u:%02u - is %u, counted %lu!\n",
						     list->name, i,
						     list->major, list->minor,
						     list->hashed[i].count, tmp_count);
				}
			}
			all_count += list->hashed[i].count;
			rcu_head_pp[i] = get_rcu_free(list, i);
			spin_unlock(&list->hashed[i].lock);
		}
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		synchronize_rcu();
		for (i=0; i<nr_hashes; i++)
			rcu_free_do_cleanup(rcu_head_pp[i]);
		rsbac_kfree(rcu_head_pp);
		if (list->dirty && (list->flags & RSBAC_LIST_PERSIST)) {
			dirty++;
			rsbac_pr_debug(lists, "%s on %02u:%02u has %u items (list is dirty)\n",
				       list->name, list->major, list->minor, all_count);
		} else 
			rsbac_pr_debug(lists, "%s on %02u:%02u has %u items\n",
				       list->name, list->major, list->minor, all_count);
		list = srcu_dereference(list->next, &reg_list_srcu);
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	lol_list = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_list) {
lol_restart:
		if(lol_list->hash_function)
			read_lock(&lol_list->hash_lock);
		nr_hashes = BIT(lol_list->hash_bits);
		rcu_head_lol_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_lol_pp));
		if (unlikely(!rcu_head_lol_pp)) {
			if(lol_list->hash_function)
				read_unlock(&lol_list->hash_lock);
			srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
			return -RSBAC_ENOMEM;
		}
		remove_count = 0;
		/* check list */
		all_count = 0;
		subitem_count = 0;
		for (i=0; i<nr_hashes; i++) {
			tmp_count = 0;
			spin_lock(&lol_list->hashed[i].lock);
			lol_item_p = lol_list->hashed[i].head;
			while (lol_item_p) {
				tmp_subcount = 0;
				lol_subitem_p = lol_item_p->head;
				while (lol_subitem_p) {
					if ((lol_subitem_p->max_age
					     && (lol_subitem_p->max_age <=
						 RSBAC_CURRENT_TIME)
					    )
					    || (lol_list->def_subdata
						&&
						!memcmp(((char *)
							 lol_subitem_p) +
							sizeof
							(*lol_subitem_p) +
							lol_list->info.
							subdesc_size,
							lol_list->
							def_subdata,
							lol_list->info.
							subdata_size)
					    )
					    ) {
						next_lol_subitem_p =
						    lol_subitem_p->next;
						do_remove_lol_subitem
						    (lol_item_p,
						     lol_subitem_p);
						rcu_free_lol_sub(lol_list, i, lol_subitem_p);
						lol_subitem_p =
						    next_lol_subitem_p;
					} else {
						tmp_subcount++;
						lol_subitem_p =
						    lol_subitem_p->next;
					}
				}
				if (tmp_subcount != lol_item_p->count) {
					if (correct) {
						rsbac_printk(KERN_WARNING "rsbac_check_lists(): correcting count mismatch for list of lists %s hash %u sublist on %02u:%02u - was %lu, counted %lu!\n",
							     lol_list->name, i,
							     lol_list->major, lol_list->minor,
							     lol_item_p->count,
							     tmp_subcount);
						lol_item_p->count =
						    tmp_subcount;
					} else {
						rsbac_printk(KERN_WARNING "rsbac_check_lists(): count mismatch for list of lists %s hash %u sublist on %02u:%02u - is %lu, counted %lu!\n",
							     lol_list->name, i,
							     lol_list->major, lol_list->minor,
							     lol_item_p->count,
							     tmp_subcount);
					}
				}
				if ((lol_item_p->max_age
				     && (lol_item_p->max_age <= RSBAC_CURRENT_TIME)
				    )
				    || (lol_list->def_data
					&& !lol_item_p->count
					&& !memcmp(((char *) lol_item_p) +
						   sizeof(*lol_item_p) +
						   lol_list->info.desc_size,
						   lol_list->def_data,
						   lol_list->info.data_size)
				    )
				    || (!lol_list->info.data_size
					&& (lol_list->flags & RSBAC_LIST_DEF_DATA)
					&& !lol_item_p->count)
				    ) {
					next_lol_item_p = lol_item_p->next;
					do_remove_lol_item(lol_list, lol_item_p, i);
					remove_count++;
					if (remove_count > rsbac_list_rcu_rate) {
						rcu_head_lol_pp[i] = get_rcu_free_lol(lol_list, i);
						spin_unlock(&lol_list->hashed[i].lock);
						if(lol_list->hash_function)
							read_unlock(&lol_list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
						rcu_rate_reached_count++;
#endif
						synchronize_rcu();
						for (i=0; i<nr_hashes; i++)
							rcu_free_do_cleanup_lol(rcu_head_lol_pp[i]);
						rsbac_kfree(rcu_head_lol_pp);
						goto lol_restart;
					}
					lol_item_p = next_lol_item_p;
				} else {
					tmp_count++;
					subitem_count += lol_item_p->count;
					lol_item_p = lol_item_p->next;
					if (tmp_count > (2 * lol_list->max_items_per_hash)) {
						tmp_count = 0;
						rsbac_printk(KERN_WARNING "rsbac_check_lists(): list of lists %s hash %u on device %02u:%02u counts an invalid number %lu of items, should be %u, skipping further checks!\n",
							     lol_list->name, i,
							     lol_list->major, lol_list->minor,
							     tmp_count, lol_list->hashed[i].count);
					}
				}
			}
			if ((tmp_count > 0) && (tmp_count != lol_list->hashed[i].count)) {
				if (correct) {
					rsbac_printk(KERN_WARNING "rsbac_check_lists(): correcting count mismatch for list of lists %s hash %u on %02u:%02u - was %u, counted %lu!\n",
						     lol_list->name, i,
						     lol_list->major, lol_list->minor,
						     lol_list->hashed[i].count, tmp_count);
				lol_list->hashed[i].count = tmp_count;
				} else {
					rsbac_printk(KERN_WARNING "rsbac_check_lists(): count mismatch for list of lists %s hash %u on %02u:%02u - is %u, counted %lu!\n",
						     lol_list->name, i,
						     lol_list->major, lol_list->minor,
						     lol_list->hashed[i].count, tmp_count);
				}
			}
			all_count += lol_list->hashed[i].count;
			spin_unlock(&lol_list->hashed[i].lock);
		}
		if(lol_list->hash_function)
			read_unlock(&lol_list->hash_lock);
		synchronize_rcu();
		for (i=0; i<nr_hashes; i++)
			rcu_free_do_cleanup_lol(rcu_head_lol_pp[i]);
		rsbac_kfree(rcu_head_lol_pp);
		if (lol_list->dirty
		    && (lol_list->flags & RSBAC_LIST_PERSIST)) {
			dirty++;
			rsbac_pr_debug(lists, "%s on %02u:%02u has %u items and %lu subitems (list is dirty)\n",
				       lol_list->name,
				       lol_list->major, lol_list->minor,
				       all_count, subitem_count);
		} else
			rsbac_pr_debug(lists, "%s on %02u:%02u has %u items and %lu subitems\n",
				       lol_list->name,
				       lol_list->major, lol_list->minor,
				       all_count, subitem_count);
		lol_list = srcu_dereference(lol_list->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	return 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_check);
#endif
int rsbac_list_check(rsbac_list_handle_t handle, const int correct)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	struct rsbac_list_item_t *next_item_p;
	u_long tmp_count;
	int i;
	struct rsbac_list_rcu_free_head_t ** rcu_head_pp = NULL;
	u_int remove_count;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(!list || (list->self != list)))
		return -RSBAC_EINVALIDLIST;

	rsbac_pr_debug(lists, "checking list %s.\n", list->name);

	remove_count = 0;
                
restart:
	if(list->hash_function)
		read_lock(&list->hash_lock);
	nr_hashes = BIT(list->hash_bits);
	rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_pp));
	if (unlikely(!rcu_head_pp)) {
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		return -RSBAC_ENOMEM;
	}
	for (i=0; i<nr_hashes; i++) {
		tmp_count = 0;
		spin_lock(&list->hashed[i].lock);
		item_p = list->hashed[i].head;
		while (item_p) {
			if ((item_p->max_age
			     && (item_p->max_age <= RSBAC_CURRENT_TIME)
			    )
			    || (list->def_data
				&& !memcmp(((char *) item_p) + sizeof(*item_p) +
					   list->info.desc_size, list->def_data,
					   list->info.data_size)
			    )
			    ) {
				next_item_p = item_p->next;
				do_remove_item(list, item_p, i);
				remove_count++;
				if (remove_count > rsbac_list_rcu_rate) {
					rcu_head_pp[i] = get_rcu_free(list, i);
					spin_unlock(&list->hashed[i].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
					rcu_rate_reached_count++;
#endif
					synchronize_rcu();
					for (i=0; i<nr_hashes; i++)
						rcu_free_do_cleanup(rcu_head_pp[i]);
					rsbac_kfree(rcu_head_pp);
					goto restart;
				}
				item_p = next_item_p;
				list->dirty = TRUE;
			} else {
				tmp_count++;
				item_p = item_p->next;
			}
		}
		if (tmp_count != list->hashed[i].count) {
			if (correct) {
				rsbac_printk(KERN_WARNING "rsbac_list_check(): correcting count mismatch for list %s hash %u on device %02u:%02u - was %u, counted %lu!\n",
					     list->name, i,
					     list->major, list->minor,
					     list->hashed[i].count, tmp_count);
				list->hashed[i].count = tmp_count;
				list->dirty = TRUE;
			} else {
				rsbac_printk(KERN_WARNING "rsbac_list_check(): count mismatch for list %s hash %u on device %02u:%02u - is %u, counted %lu!\n",
					     list->name, i,
					     list->major, list->minor,
					     list->hashed[i].count, tmp_count);
			}
		}
		rcu_head_pp[i] = get_rcu_free(list, i);
		spin_unlock(&list->hashed[i].lock);
	}
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	synchronize_rcu();
	for (i=0; i<nr_hashes; i++)
		rcu_free_do_cleanup(rcu_head_pp[i]);
	rsbac_kfree(rcu_head_pp);
	return 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_check);
#endif
int rsbac_list_lol_check(rsbac_list_handle_t handle, const int correct)
{
	struct rsbac_list_lol_reg_item_t *lol_list;
	struct rsbac_list_lol_item_t *lol_item_p;
	struct rsbac_list_lol_item_t *next_lol_item_p;
	struct rsbac_list_item_t *lol_subitem_p;
	struct rsbac_list_item_t *next_lol_subitem_p;
	u_long tmp_count;
	u_long tmp_subcount;
	int i;
	struct rsbac_list_rcu_free_head_lol_t ** rcu_head_lol_pp;
	u_int remove_count;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	lol_list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(!lol_list || (lol_list->self != lol_list)))
		return -RSBAC_EINVALIDLIST;

	rsbac_pr_debug(lists, "checking list %s.\n", lol_list->name);

	remove_count = 0;

restart:
	if(lol_list->hash_function)
		read_lock(&lol_list->hash_lock);
	nr_hashes = BIT(lol_list->hash_bits);
	rcu_head_lol_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_lol_pp));
	if (unlikely(!rcu_head_lol_pp)) {
		if(lol_list->hash_function)
			read_unlock(&lol_list->hash_lock);
		return -RSBAC_ENOMEM;
	}
	for (i=0; i<nr_hashes; i++) {
		tmp_count = 0;
		spin_lock(&lol_list->hashed[i].lock);
		lol_item_p = lol_list->hashed[i].head;
		while (lol_item_p) {
			if ((lol_item_p->max_age
			     && (lol_item_p->max_age <= RSBAC_CURRENT_TIME)
			    )
			    || (lol_list->def_data
				&& !lol_item_p->count
				&& !memcmp(((char *) lol_item_p) +
					   sizeof(*lol_item_p) +
					   lol_list->info.desc_size,
					   lol_list->def_data,
					   lol_list->info.data_size)
			    )
			    || (!lol_list->info.data_size
				&& (lol_list->flags & RSBAC_LIST_DEF_DATA)
				&& !lol_item_p->count)
			    ) {
				next_lol_item_p = lol_item_p->next;
				do_remove_lol_item(lol_list, lol_item_p, i);
				remove_count++;
				if (remove_count > rsbac_list_rcu_rate) {
					rcu_head_lol_pp[i] = get_rcu_free_lol(lol_list, i);
					spin_unlock(&lol_list->hashed[i].lock);
					if(lol_list->hash_function)
						read_unlock(&lol_list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
					rcu_rate_reached_count++;
#endif
					synchronize_rcu();
					for (i=0; i<nr_hashes; i++)
						rcu_free_do_cleanup_lol(rcu_head_lol_pp[i]);
					rsbac_kfree(rcu_head_lol_pp);
					goto restart;
				}
				lol_item_p = next_lol_item_p;
			} else {
				tmp_count++;
				tmp_subcount = 0;
				lol_subitem_p = lol_item_p->head;
				while (lol_subitem_p) {
					if ((lol_subitem_p->max_age
					     && (lol_subitem_p->max_age <=
						 RSBAC_CURRENT_TIME)
					    )
					    || (lol_list->def_subdata
						&& !memcmp(((char *) lol_subitem_p)
							   +
							   sizeof(*lol_subitem_p) +
							   lol_list->info.
							   subdesc_size,
		 					   lol_list->def_subdata,
							   lol_list->info.
							   subdata_size)
					    )
					    ) {
						next_lol_subitem_p =
						    lol_subitem_p->next;
						do_remove_lol_subitem(lol_item_p,
								      lol_subitem_p);
						rcu_free_lol_sub(lol_list, i, lol_subitem_p);
						lol_subitem_p = next_lol_subitem_p;
					} else {
						tmp_subcount++;
						lol_subitem_p =
						    lol_subitem_p->next;
					}
				}
				if (tmp_subcount != lol_item_p->count) {
					if (correct) {
						rsbac_printk(KERN_WARNING "rsbac_list_lol_check(): correcting count mismatch for list of lists %s hash %u sublist on %02u:%02u - was %lu, counted %lu!\n",
							     lol_list->name, i,
							     lol_list->major, lol_list->minor,
							     lol_item_p->count,
							     tmp_subcount);
						lol_item_p->count = tmp_subcount;
					} else {
						rsbac_printk(KERN_WARNING "rsbac_list_lol_check(): count mismatch for list of lists %s hash %u sublist on %02u:%02u - is %lu, counted %lu!\n",
							     lol_list->name, i,
							     lol_list->major, lol_list->minor,
							     lol_item_p->count,
							     tmp_subcount);
					}
				}
	 			lol_item_p = lol_item_p->next;
			}
		}
		if (tmp_count != lol_list->hashed[i].count) {
			if (correct) {
				rsbac_printk(KERN_WARNING "rsbac_list_lol_check(): correcting count mismatch for list of lists %s hash %u on %02u:%02u - was %u, counted %lu!\n",
					     lol_list->name, i,
					     lol_list->major, lol_list->minor,
					     lol_list->hashed[i].count, tmp_count);
				lol_list->hashed[i].count = tmp_count;
			} else {
				rsbac_printk(KERN_WARNING "rsbac_list_lol_check(): count mismatch for list of lists %s hash %u on %02u:%02u - is %u, counted %lu!\n",
					     lol_list->name, i,
					     lol_list->major, lol_list->minor,
					     lol_list->hashed[i].count, tmp_count);
			}
		}
		rcu_head_lol_pp[i] = get_rcu_free_lol(lol_list, i);
		spin_unlock(&lol_list->hashed[i].lock);
	}
	if(lol_list->hash_function)
		read_unlock(&lol_list->hash_lock);
	synchronize_rcu();
	for (i=0; i<nr_hashes; i++)
		rcu_free_do_cleanup_lol(rcu_head_lol_pp[i]);
	rsbac_kfree(rcu_head_lol_pp);
	return 0;
}


/********************/
/* Registration     */
/********************/

/* get generic list registration version */
inline rsbac_version_t rsbac_list_version(void)
{
	return RSBAC_LIST_VERSION;
}

#if defined(CONFIG_RSBAC_PROC)
static int backup_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, backup_proc_show, NULL);
}

static const struct proc_ops backup_proc_ops = {
       .proc_open           = backup_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};

static int lol_backup_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lol_backup_proc_show, NULL);
}

static const struct proc_ops lol_backup_proc_ops = {
       .proc_open           = lol_backup_proc_open,
       .proc_read           = seq_read,
       .proc_lseek          = seq_lseek,
       .proc_release        = single_release,
};
#endif

/* register a new list */
/*
 * If list with same name exists in memory, error -RSBAC_EEXISTS is returned.
 * If list with same name and key exists on device, it is restored depending on the flags.
 * If list with same name, but different key exists, access is denied (error -EPERM).
 *
 * ds_version: for binary modules, must be RSBAC_LIST_VERSION. If version differs, return error.
 * handle_p: for all list accesses, an opaque handle is put into *handle_p.
 * key: positive, secret __u32 key, which must be the same as in on-disk version, if persistent
 * list_version: positive __u32 version number for the list. If old on-disk version is
   different, upconversion is tried (depending on flags and get_conv function)
 * flags: see flag values
 * desc_size: size of the descriptor (error is returned, if value is 0 or list exists and value differs)
 * data_size: size of data (error is returned, if list exists and value differs). Can be 0 for sets.
 * compare: for lookup and list optimization, can be NULL, then
   memcmp(desc1, desc2, desc_size) is used
 * def_data: default data value for flag RSBAC_LIST_DEF_DATA
   (if NULL, flag is cleared)
 * name: the on-disk name, must be distinct and max. 7 or 8.2 chars
   (only used for statistics, if non-persistent)
 * major: major of the device to read list from or to save list to - use 0 for root dev
   (ignored, if non-persistent)
 * minor: minor of the device to read list from or to save list to - use 0 for root dev
   (ignored, if non-persistent)
 * hash_bits: Number of bits of hashes for this list, minimum is 1,
   maximum is rsbac_list_max_hash_bits,
   which is derived from CONFIG_RSBAC_LIST_MAX_HASH_BITS and must not be more than 31
   Number of hashes is 2^hash_bits.
   If > maximum, it will be reduced to maximum automatically. If 0, no hashing.
 * hash_function: Hash function(desc,hash_bits), must always return a value
   from 0 to 2^hash_bits - 1.
 * old_base_name: If not NULL and persistent list with name cannot be read,
   try to read all old_base_name<n> with n from 0 to 31.
 */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_register_hashed);
#endif
int rsbac_list_register_hashed(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_get_conv_t * get_conv,
			void *def_data, char *name,
			__u32 major, __u32 minor,
			__u8 hash_bits,
			rsbac_list_hash_function_t hash_function,
			char * old_base_name)
{
	struct rsbac_list_reg_item_t *reg_item_p;
	struct rsbac_list_reg_item_t *new_reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(ds_version != RSBAC_LIST_VERSION)) {
		if (name) {
			rsbac_printk(KERN_WARNING "rsbac_list_register: wrong ds_version %u for list %s, expected %u!\n",
				     ds_version, name, RSBAC_LIST_VERSION);
		}
		return -RSBAC_EINVALIDVERSION;
	}
	if (unlikely(!handle_p || !info_p))
		return -RSBAC_EINVALIDPOINTER;
	*handle_p = NULL;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!info_p->key || !info_p->version || !info_p->desc_size))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(info_p->max_age > RSBAC_LIST_MAX_AGE_LIMIT))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(info_p->desc_size + info_p->data_size >
	    RSBAC_LIST_MAX_ITEM_SIZE))
		return -RSBAC_EINVALIDVALUE;
	if (hash_bits > rsbac_list_max_hash_bits)
		hash_bits = rsbac_list_max_hash_bits;
	if (!hash_function || !hash_bits) {
		hash_bits = 0;
		flags &= ~RSBAC_LIST_AUTO_HASH_RESIZE;
	}
	if (name) {
		struct rsbac_list_lol_reg_item_t *lol_reg_item_p;

		srcu_idx = srcu_read_lock(&reg_list_srcu);
		reg_item_p = lookup_reg_name(name, major, minor);
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		if (reg_item_p) {
			rsbac_pr_debug(lists, "list name %s already exists on device %02u:%02u!\n",
				       name, major, minor);
			return -RSBAC_EEXISTS;
		}
		srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
		lol_reg_item_p = lookup_lol_reg_name(name, major, minor);
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		if (lol_reg_item_p) {
			rsbac_pr_debug(lists, "list name %s already exists on device %02u:%02u!\n",
				       name, major, minor);
			return -RSBAC_EEXISTS;
		}
	} else if (flags & RSBAC_LIST_PERSIST) {
		rsbac_printk(KERN_WARNING "rsbac_list_register: trial to register persistent list without name.\n");
		return -RSBAC_EINVALIDVALUE;
	}

	if (flags & RSBAC_LIST_PERSIST) {
		if (RSBAC_IS_AUTO_DEV(major, minor)) {
			major = rsbac_root_dev_major;
			minor = rsbac_root_dev_minor;
		}
		if (!major)
			flags &= ~RSBAC_LIST_PERSIST;
	}
	rsbac_pr_debug(lists, "registering list %s for device %02u:%02u.\n",
		       name, major, minor);
	new_reg_item_p =
	    create_reg(info_p, flags, compare, get_conv, def_data, name,
		       major, minor, hash_bits, hash_function, old_base_name);
	if (unlikely(!new_reg_item_p)) {
		return -RSBAC_ECOULDNOTADDITEM;
	}
	/* Restore from disk, but only for real device mounts */
	if ((flags & RSBAC_LIST_PERSIST)
	    && major
	    && !rsbac_list_noread
	    ) {
		rsbac_pr_debug(lists, "restoring list %s from device %02u:%02u.\n",
			       name, major, minor);
		err = read_list(new_reg_item_p);
		/* not found is no error */
		if (err == -RSBAC_ENOTFOUND)
			err = 0;
		else if (err) {
			char tmp[RSBAC_MAXNAMELEN];

			if (rsbac_list_recover) {
				rsbac_printk(KERN_WARNING "restoring list %s from device %02u:%02u failed with error %s, rsbac_list_recover is set so registering anyway.\n",
					name,
					major, minor,
					get_error_name(tmp, err));
				err = 0;
			} else {
				rsbac_printk(KERN_WARNING "restoring list %s from device %02u:%02u failed with error %s, unregistering list.\n",
					name,
					major, minor,
					get_error_name(tmp, err));
				clear_reg(new_reg_item_p);
				return err;
			}
		} else
			rsbac_pr_debug(lists, "restoring list %s from device %02u:%02u was successful.\n",
				       name, major, minor);
	}

	spin_lock(&reg_head.lock);
	reg_item_p = add_reg(new_reg_item_p);
	spin_unlock(&reg_head.lock);
	if (unlikely(!reg_item_p)) {
		rsbac_printk(KERN_WARNING "rsbac_list_register: inserting list %s failed!\n",
			     name);
		/* cleanup */
		clear_reg(new_reg_item_p);
		return -RSBAC_ECOULDNOTADDITEM;
	}

	/* finish */
#if defined(CONFIG_RSBAC_PROC)
	/* create proc entry, if requested */
	if (flags & RSBAC_LIST_BACKUP) {
		reg_item_p->proc_entry_p =
		proc_create_data(reg_item_p->name, S_IFREG | S_IRUGO,
				      proc_rsbac_backup_p, &backup_proc_ops,
				      (void *) reg_item_p);
	} else {
		reg_item_p->proc_entry_p = NULL;
	}
#endif
	*handle_p = reg_item_p;
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_register);
#endif
int rsbac_list_register(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_get_conv_t * get_conv,
			void *def_data, char *name, __u32 major, __u32 minor)
{
	return rsbac_list_register_hashed(ds_version, handle_p, info_p, flags,
				compare, get_conv, def_data, name, major, minor,
  				1, NULL, NULL);
}

/* register a new list of lists */
/*
 * If list with same name exists in memory, error -RSBAC_EEXISTS is returned.
 * If list with same name and key exists on device, it is restored depending on the flags.
 * If list with same name, but different key exists, access is denied (error -EPERM).
 *
 * ds_version: for binary modules, must be RSBAC_LIST_VERSION. If version differs, return error.
 * handle_p: for all list accesses, an opaque handle is put into *handle_p.
 * key: positive, secret __u32 key, which must be the same as in on-disk version, if persistent
 * list_version: positive __u32 version number for the list. If old on-disk version is
   different, upconversion is tried (depending on flags and get_conv function)
 * flags: see flag values
 * desc_size: size of the descriptor (error is returned, if value is 0 or list exists and value differs)
 * subdesc_size: size of the sublist descriptor (error is returned, if value is 0 or list exists
   and value differs)
 * data_size: size of data (error is returned, if list exists and value differs). Can be 0 for sets.
 * subdata_size: size of sublist data (error is returned, if list exists and value differs).
   Can be 0 for sets.
 * compare: for lookup and list optimization, can be NULL, then
   memcmp(desc1, desc2, desc_size) is used
 * subcompare: for item lookup and optimization of sublist, can be NULL, then
   memcmp(desc1, desc2, desc_size) is used
 * def_data: default data value for flag RSBAC_LIST_DEF_DATA
   (if NULL, flag is cleared)
 * def_subdata: default subdata value for flag RSBAC_LIST_DEF_SUBDATA
   (if NULL, flag is cleared)
 * name: the on-disk name, must be distinct and max. 7 or 8.2 chars
   (only used for info, if non-persistent)
 * major: major of the device to read list from or to save list to - use 0 for root dev
   (ignored, if non-persistent)
 * minor: minor of the device to read list from or to save list to - use 0 for root dev
   (ignored, if non-persistent)
 * hash_bits: Number of bits of hashes for this list, minimum is 1,
   maximum is rsbac_list_max_hash_bits,
   which is derived from CONFIG_RSBAC_LIST_MAX_HASH_BITS and must not be more than 31
   Number of hashes is 2^hash_bits.
   If > maximum, it will be reduced to maximum automatically. If 0, no hashing.
 * hash_function: Hash function(desc,hash_bits), must always return a value
   from 0 to 2^hash_bits - 1.
 * old_base_name: If not NULL and persistent list with name cannot be read,
   try to read all old_base_name<n> with n from 0 to 31.
 */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_register_hashed);
#endif
int rsbac_list_lol_register_hashed(rsbac_version_t ds_version,
			rsbac_list_handle_t * handle_p,
			struct rsbac_list_lol_info_t *info_p,
			u_int flags,
			rsbac_list_compare_function_t * compare,
			rsbac_list_compare_function_t * subcompare,
			rsbac_list_get_conv_t * get_conv,
			rsbac_list_get_conv_t * get_subconv,
			void *def_data,
			void *def_subdata, char *name, __u32 major, __u32 minor,
			__u8 hash_bits,
			rsbac_list_hash_function_t hash_function,
			char * old_base_name)
{
	struct rsbac_list_lol_reg_item_t *reg_item_p;
	struct rsbac_list_lol_reg_item_t *new_reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(ds_version != RSBAC_LIST_VERSION))
		return -RSBAC_EINVALIDVERSION;
	if (unlikely(!handle_p))
		return -RSBAC_EINVALIDPOINTER;
	*handle_p = NULL;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!info_p->key || !info_p->version || !info_p->desc_size))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(info_p->max_age > RSBAC_LIST_MAX_AGE_LIMIT))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(info_p->desc_size + info_p->data_size >
	    RSBAC_LIST_MAX_ITEM_SIZE))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(info_p->subdesc_size + info_p->subdata_size >
	    RSBAC_LIST_MAX_ITEM_SIZE))
		return -RSBAC_EINVALIDVALUE;
	if (hash_bits > rsbac_list_max_hash_bits)
		hash_bits = rsbac_list_max_hash_bits;
	if (!hash_function || !hash_bits) {
		hash_bits = 0;
		flags &= ~RSBAC_LIST_AUTO_HASH_RESIZE;
	}
	if (name) {
		struct rsbac_list_reg_item_t *std_reg_item_p;

		srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
		reg_item_p = lookup_lol_reg_name(name, major, minor);
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		if (reg_item_p) {
			rsbac_pr_debug(lists, "list name %s already exists on device %02u:%02u!\n",
				       name, major, minor);
			return -RSBAC_EEXISTS;
		}
		srcu_idx = srcu_read_lock(&reg_list_srcu);
		std_reg_item_p = lookup_reg_name(name, major, minor);
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		if (std_reg_item_p) {
			rsbac_pr_debug(lists, "list name %s already exists on device %02u:%02u!\n",
				       name, major, minor);
			return -RSBAC_EEXISTS;
		}
	} else if (flags & RSBAC_LIST_PERSIST) {
		rsbac_printk(KERN_WARNING "rsbac_list_lol_register: trial to register persistent list of lists without name.\n");
		return -RSBAC_EINVALIDVALUE;
	}

	if (flags & RSBAC_LIST_PERSIST) {
		if (RSBAC_IS_AUTO_DEV(major, minor)) {
			major = rsbac_root_dev_major;
			minor = rsbac_root_dev_minor;
		}
		if (!major)
			flags &= ~RSBAC_LIST_PERSIST;
	}
	rsbac_pr_debug(lists, "registering list of lists %s.\n",
		       name);
	new_reg_item_p = create_lol_reg(info_p, flags, compare, subcompare,
					get_conv, get_subconv,
					def_data, def_subdata,
					name, major, minor,
					hash_bits, hash_function,
					old_base_name);
	if (unlikely(!new_reg_item_p)) {
		return -RSBAC_ECOULDNOTADDITEM;
	}
	/* Restore from disk, but only for real device mounts */
	if ((flags & RSBAC_LIST_PERSIST)
	    && major
	    && !rsbac_list_noread
	    ) {
		rsbac_pr_debug(lists, "restoring list %s from device %02u:%02u.\n",
			       name, major, minor);
		err = read_lol_list(new_reg_item_p);
		/* not found is no error */
		if (err == -RSBAC_ENOTFOUND)
			err = 0;
		else if (err) {
#ifdef CONFIG_RSBAC_DEBUG
			char tmp[RSBAC_MAXNAMELEN];
#endif

			rsbac_pr_debug(lists, "restoring list %s from device %02u:%02u failed with error %s, unregistering list.\n",
				       name,
				       major, minor,
				       get_error_name(tmp, err));
			clear_lol_reg(new_reg_item_p);
			return err;
		} else
			rsbac_pr_debug(lists, "restoring list %s from device %02u:%02u was successful.\n",
				       name, major, minor);
	}

	spin_lock(&lol_reg_head.lock);
	reg_item_p = add_lol_reg(new_reg_item_p);
	spin_unlock(&lol_reg_head.lock);
	if (unlikely(!reg_item_p)) {
		rsbac_printk(KERN_WARNING "rsbac_list_lol_register: inserting list %s failed!\n",
			     name);
		/* cleanup */
		clear_lol_reg(new_reg_item_p);
		return -RSBAC_ECOULDNOTADDITEM;
	}

	/* finish */
#if defined(CONFIG_RSBAC_PROC)
	/* create proc entry, if requested */
	if (flags & RSBAC_LIST_BACKUP) {
		reg_item_p->proc_entry_p =
		    proc_create_data(reg_item_p->name, S_IFREG | S_IRUGO,
				      proc_rsbac_backup_p, &lol_backup_proc_ops,
				      (void *) reg_item_p);
	} else {
		reg_item_p->proc_entry_p = NULL;
	}
#endif
	*handle_p = reg_item_p;
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_register);
#endif
int rsbac_list_lol_register(rsbac_version_t ds_version,
			    rsbac_list_handle_t * handle_p,
			    struct rsbac_list_lol_info_t *info_p,
			    u_int flags,
			    rsbac_list_compare_function_t * compare,
			    rsbac_list_compare_function_t * subcompare,
			    rsbac_list_get_conv_t * get_conv,
			    rsbac_list_get_conv_t * get_subconv,
			    void *def_data,
			    void *def_subdata, char *name, __u32 major, __u32 minor) {
	return rsbac_list_lol_register_hashed (ds_version, handle_p, info_p,
				flags, compare, subcompare, get_conv,
				get_subconv, def_data, def_subdata,
				name, major, minor,
  				1, NULL, NULL);
}

/* destroy list */
/* list is destroyed, disk file is deleted */
/* list must have been opened with register */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_destroy);
#endif
int rsbac_list_destroy(rsbac_list_handle_t * handle_p,
		       rsbac_list_key_t key)
{
	struct rsbac_list_reg_item_t *reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(!handle_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!*handle_p))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	reg_item_p =
	    lookup_reg((struct rsbac_list_reg_item_t *) *handle_p);
	if (!reg_item_p) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_destroy: destroying list failed due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_destroy: destroying list %s denied due to invalid key!\n",
			     reg_item_p->name);
		return -EPERM;
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	rsbac_pr_debug(lists, "destroying list %s.\n",
		       reg_item_p->name);
#if defined(CONFIG_RSBAC_PROC)
	/* delete proc entry, if it exists */
	if ((reg_item_p->flags & RSBAC_LIST_BACKUP)
	    && reg_item_p->proc_entry_p) {
		remove_proc_entry(reg_item_p->name, proc_rsbac_backup_p);
		reg_item_p->proc_entry_p = NULL;
	}
#endif

	spin_lock(&reg_head.lock);
	remove_reg(reg_item_p);
	*handle_p = NULL;
	spin_unlock(&reg_head.lock);
	synchronize_srcu(&reg_list_srcu);
	synchronize_rcu();
	/* now we can remove the item from memory */
	clear_reg(reg_item_p);
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_destroy);
#endif
int rsbac_list_lol_destroy(rsbac_list_handle_t * handle_p,
			   rsbac_list_key_t key)
{
	struct rsbac_list_lol_reg_item_t *reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(!handle_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!*handle_p))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	reg_item_p =
	    lookup_lol_reg((struct rsbac_list_lol_reg_item_t *) *handle_p);
	if (!reg_item_p) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_destroy: destroying list failed due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_destroy: destroying list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	rsbac_pr_debug(lists, "destroying list %s.\n",
		       reg_item_p->name);
#if defined(CONFIG_RSBAC_PROC)
	/* delete proc entry, if it exists */
	if ((reg_item_p->flags & RSBAC_LIST_BACKUP)
	    && reg_item_p->proc_entry_p) {
		remove_proc_entry(reg_item_p->name, proc_rsbac_backup_p);
		reg_item_p->proc_entry_p = NULL;
	}
#endif

	spin_lock(&lol_reg_head.lock);
	remove_lol_reg(reg_item_p);
	spin_unlock(&lol_reg_head.lock);
	synchronize_srcu(&lol_reg_list_srcu);
	/* now we can remove the item from memory */
	clear_lol_reg(reg_item_p);
	return err;
}

/* detach from list */
/* list is saved and removed from memory. Call register for new access. */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_detach);
#endif
int rsbac_list_detach(rsbac_list_handle_t * handle_p, rsbac_list_key_t key)
{
	struct rsbac_list_reg_item_t *reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(!handle_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!*handle_p))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	reg_item_p = lookup_reg((struct rsbac_list_reg_item_t *) *handle_p);
	if (!reg_item_p) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_detach: detaching list failed due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_detach: detaching list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
#if defined(CONFIG_RSBAC_PROC)
	/* delete proc entry, if it exists */
	if ((reg_item_p->flags & RSBAC_LIST_BACKUP)
	    && reg_item_p->proc_entry_p) {
		remove_proc_entry(reg_item_p->name, proc_rsbac_backup_p);
		reg_item_p->proc_entry_p = NULL;
	}
#endif
#ifndef CONFIG_RSBAC_NO_WRITE
	/* final write, if dirty etc. */
	if ((reg_item_p->flags & RSBAC_LIST_PERSIST)
	    && reg_item_p->dirty && !reg_item_p->no_write
	    && !rsbac_debug_no_write) {
	    	struct vfsmount *mnt_p;
		struct rsbac_list_write_head_t write_head;
		struct rsbac_list_write_item_t *write_item_p;

		mnt_p = rsbac_get_vfsmount(reg_item_p->major, reg_item_p->minor);
		if (mnt_p && rsbac_writable(mnt_p->mnt_sb)) {
			reg_item_p->dirty = FALSE;
			err = fill_buffer(reg_item_p, &write_item_p);
			if (!err) {
				write_head.head = write_item_p;
				write_head.tail = write_item_p;
				write_head.count = 1;
				rsbac_list_write_buffers(write_head);
			} else {
				if (err != -RSBAC_ENOTWRITABLE) {
					rsbac_printk(KERN_WARNING "rsbac_list_detach(): fill_buffer() for list %s returned error %i\n",
						     reg_item_p->name, err);
				}
			}
		}
	}
#endif
	/* disable handle */
	*handle_p = NULL;
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	/* too bad that the list might have been changed again - we do not care anymore */
	spin_lock(&reg_head.lock);
	remove_reg(reg_item_p);
	spin_unlock(&reg_head.lock);
	synchronize_srcu(&reg_list_srcu);
	synchronize_rcu();
	/* now we can remove the item from memory */
	clear_reg(reg_item_p);
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_detach);
#endif
int rsbac_list_lol_detach(rsbac_list_handle_t * handle_p,
			  rsbac_list_key_t key)
{
	struct rsbac_list_lol_reg_item_t *reg_item_p;
	int err = 0;
	int srcu_idx;

	if (unlikely(!handle_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!*handle_p))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	reg_item_p = lookup_lol_reg((struct rsbac_list_lol_reg_item_t *) *handle_p);
	if (!reg_item_p) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_detach: detaching list failed due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_detach: detaching list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
#if defined(CONFIG_RSBAC_PROC)
	/* delete proc entry, if it exists */
	if ((reg_item_p->flags & RSBAC_LIST_BACKUP)
	    && reg_item_p->proc_entry_p) {
		remove_proc_entry(reg_item_p->name, proc_rsbac_backup_p);
		reg_item_p->proc_entry_p = NULL;
	}
#endif
#ifndef CONFIG_RSBAC_NO_WRITE
	/* final write, if dirty etc. */
	if ((reg_item_p->flags & RSBAC_LIST_PERSIST)
	    && reg_item_p->dirty && !reg_item_p->no_write
	    && !rsbac_debug_no_write) {
		struct rsbac_list_lol_write_head_t write_head;
		struct rsbac_list_lol_write_item_t *write_item_p;
	    	struct vfsmount *mnt_p;

		mnt_p = rsbac_get_vfsmount(reg_item_p->major, reg_item_p->minor);
		if (mnt_p && rsbac_writable(mnt_p->mnt_sb)) {
			reg_item_p->dirty = FALSE;
			err = fill_lol_buffer(reg_item_p, &write_item_p);
			if (!err) {
				write_head.head = write_item_p;
				write_head.tail = write_item_p;
				write_head.count = 1;
				rsbac_list_write_lol_buffers(write_head);
			} else {
				if (err != -RSBAC_ENOTWRITABLE) {
					rsbac_printk(KERN_WARNING "rsbac_list_lol_detach(): fill_lol_buffer() for list %s returned error %i\n",
						     reg_item_p->name, err);
				}
			}
		}
	}
#endif
	/* disable handle */
	*handle_p = NULL;
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	/* too bad that the list might have been changed again - we do not care anymore */
	spin_lock(&lol_reg_head.lock);
	remove_lol_reg(reg_item_p);
	spin_unlock(&lol_reg_head.lock);
	synchronize_srcu(&lol_reg_list_srcu);
	/* now we can remove the item from memory */
	clear_lol_reg(reg_item_p);
	return err;
}

/* set list's no_write flag */
/* TRUE: do not write to disk, FALSE: writing allowed */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_no_write);
#endif
int rsbac_list_no_write(rsbac_list_handle_t handle, rsbac_list_key_t key,
			rsbac_boolean_t no_write)
{
	struct rsbac_list_reg_item_t *reg_item_p;
	int srcu_idx;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely((no_write != FALSE) && (no_write != TRUE)))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	reg_item_p = lookup_reg((struct rsbac_list_reg_item_t *) handle);
	if (!reg_item_p) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_no_write: setting no_write for list denied due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_no_write: setting no_write for list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
	reg_item_p->no_write = no_write;
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	return 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_no_write);
#endif
int rsbac_list_lol_no_write(rsbac_list_handle_t handle,
			    rsbac_list_key_t key, rsbac_boolean_t no_write)
{
	struct rsbac_list_lol_reg_item_t *reg_item_p;
	int srcu_idx;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely((no_write != FALSE) && (no_write != TRUE)))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	reg_item_p = lookup_lol_reg((struct rsbac_list_lol_reg_item_t *) handle);
	if (!reg_item_p) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_no_write: setting no_write for list denied due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_no_write: setting no_write for list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
	reg_item_p->no_write = no_write;
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	return 0;
}

/* set list's max_items_per_hash */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_max_items);
#endif
int rsbac_list_max_items(rsbac_list_handle_t handle, rsbac_list_key_t key,
			u_int max_items)
{
	struct rsbac_list_reg_item_t *reg_item_p;
	int srcu_idx;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	reg_item_p = lookup_reg((struct rsbac_list_reg_item_t *) handle);
	if (!reg_item_p) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_max_items: setting max_items_per_hash for list denied due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_max_items: setting max_items_per_hash for list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
	if (!max_items)
		max_items = RSBAC_LIST_MAX_NR_ITEMS;
	reg_item_p->max_items_per_hash = rsbac_min(max_items, RSBAC_LIST_MAX_NR_ITEMS_LIMIT);
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	return 0;
}

/* set list's max_items_per_hash and max_subitems*/
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_max_items);
#endif
int rsbac_list_lol_max_items(rsbac_list_handle_t handle, rsbac_list_key_t key,
			u_int max_items, u_int max_subitems)
{
	struct rsbac_list_lol_reg_item_t *reg_item_p;
	int srcu_idx;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	reg_item_p = lookup_lol_reg((struct rsbac_list_lol_reg_item_t *) handle);
	if (!reg_item_p) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_max_items: setting max_items_per_hash for list denied due to invalid handle!\n");
		return -RSBAC_EINVALIDLIST;
	}
	if (reg_item_p->info.key != key) {
		srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
		rsbac_printk(KERN_WARNING "rsbac_list_lol_max_items: setting max_items_per_hash for list %s denied due to invalid key %u!\n",
			     reg_item_p->name, key);
		return -EPERM;
	}
	if (!max_items)
		max_items = RSBAC_LIST_MAX_NR_ITEMS;
	if (!max_subitems)
		max_subitems = RSBAC_LIST_MAX_NR_SUBITEMS;
	reg_item_p->max_items_per_hash = rsbac_min(max_items, RSBAC_LIST_MAX_NR_ITEMS_LIMIT);
	reg_item_p->max_subitems = rsbac_min(max_subitems, RSBAC_LIST_MAX_NR_ITEMS_LIMIT);
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);
	return 0;
}


/********************/
/* Transactions     */
/********************/

#ifdef CONFIG_RSBAC_LIST_TRANS
static int do_commit(rsbac_list_ta_number_t ta_number)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_lol_reg_item_t *lol_list;
	int i;
	struct rsbac_list_rcu_free_head_t * rcu_head_p;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;
	int srcu_idx;
	int srcu_idx2;
	u_int nr_hashes;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	srcu_idx2 = srcu_read_lock(&lol_reg_list_srcu);
	list = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (list) {
		if(list->hash_function)
			read_lock(&list->hash_lock);
		nr_hashes = BIT(list->hash_bits);
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&list->hashed[i].lock);
			if (list->hashed[i].ta_copied == ta_number) {
				remove_all_items(list, i);
				rcu_assign_pointer(list->hashed[i].head, list->hashed[i].ta_head);
				rcu_assign_pointer(list->hashed[i].tail, list->hashed[i].ta_tail);
				rcu_assign_pointer(list->hashed[i].curr, list->hashed[i].ta_curr);
				list->hashed[i].count = list->hashed[i].ta_count;
				list->hashed[i].ta_copied = 0;
				rcu_assign_pointer(list->hashed[i].ta_head, NULL);
				rcu_assign_pointer(list->hashed[i].ta_tail, NULL);
				rcu_assign_pointer(list->hashed[i].ta_curr, NULL);
				list->hashed[i].ta_count = 0;
				list->dirty = TRUE;
			}
			rcu_head_p = get_rcu_free(list, i);
			spin_unlock(&list->hashed[i].lock);
			do_call_rcu(rcu_head_p);
		}
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		list = srcu_dereference(list->next, &reg_list_srcu);
	}
	lol_list = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_list) {
		if(lol_list->hash_function)
			read_lock(&lol_list->hash_lock);
		nr_hashes = BIT(lol_list->hash_bits);
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&lol_list->hashed[i].lock);
			if (lol_list->hashed[i].ta_copied == ta_number) {
				remove_all_lol_items(lol_list, i);
				rcu_assign_pointer(lol_list->hashed[i].head, lol_list->hashed[i].ta_head);
				rcu_assign_pointer(lol_list->hashed[i].tail, lol_list->hashed[i].ta_tail);
				rcu_assign_pointer(lol_list->hashed[i].curr, lol_list->hashed[i].ta_curr);
				lol_list->hashed[i].count = lol_list->hashed[i].ta_count;
				lol_list->hashed[i].ta_copied = 0;
				rcu_assign_pointer(lol_list->hashed[i].ta_head, NULL);
				rcu_assign_pointer(lol_list->hashed[i].ta_tail, NULL);
				rcu_assign_pointer(lol_list->hashed[i].ta_curr, NULL);
				lol_list->hashed[i].ta_count = 0;
				lol_list->dirty = TRUE;
			}
			rcu_head_lol_p = get_rcu_free_lol(lol_list, i);
			spin_unlock(&lol_list->hashed[i].lock);
			do_call_rcu_lol(rcu_head_lol_p);
		}
		if(lol_list->hash_function)
			read_unlock(&lol_list->hash_lock);
		lol_list = srcu_dereference(lol_list->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx2);
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	return 0;
}

int rsbac_list_ta_commit(rsbac_list_ta_number_t ta_number, char *password)
{
	int err;
	struct rsbac_list_ta_data_t ta_data;

	rsbac_printk(KERN_INFO "rsbac_list_ta_commit(): starting commit of transaction %u\n",
		     ta_number);
	err = rsbac_list_get_data(ta_handle, &ta_number, &ta_data);
	if (err)
		return err;
	if ((RSBAC_UID_NUM(ta_data.commit_uid) != RSBAC_ALL_USERS)
	    && (ta_data.commit_uid != (rsbac_get_vset(),__kuid_val(current_uid())))
	    )
		return -EPERM;

	if (ta_data.password[0]) {
		if (!password)
			return -EPERM;
		if (strncmp
		    (ta_data.password, password,
		     RSBAC_LIST_TA_MAX_PASSLEN))
			return -EPERM;
	}
	rsbac_printk(KERN_INFO "rsbac_list_ta_commit(): transaction %u data verified\n",
		     ta_number);
	spin_lock(&ta_lock);
	while (ta_committing) {
		spin_unlock(&ta_lock);
		msleep_interruptible(100);
		spin_lock(&ta_lock);
	}
	rsbac_list_remove(ta_handle, &ta_number);
	ta_committing = TRUE;
	spin_unlock(&ta_lock);

	rsbac_printk(KERN_INFO "rsbac_list_ta_commit(): committing transaction %u now\n",
		     ta_number);

	err = do_commit(ta_number);
	ta_committing = FALSE;
#ifdef CONFIG_RSBAC_FD_CACHE
	if (!err)
		rsbac_fd_cache_invalidate_all();
#endif
	wake_up(&ta_wait);
	rsbac_printk(KERN_INFO "rsbac_list_ta_commit(): committed transaction %u\n",
		     ta_number);
	return err;
}

static int do_forget(rsbac_list_ta_number_t ta_number)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_lol_reg_item_t *lol_list;
	int i;
	struct rsbac_list_rcu_free_head_t * rcu_head_p;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;
	int srcu_idx;
	int srcu_idx2;
	u_int nr_hashes;

	spin_lock(&ta_lock);
	while (ta_committing) {
		spin_unlock(&ta_lock);
		msleep_interruptible(100);
		spin_lock(&ta_lock);
	}
	rsbac_list_remove(ta_handle, &ta_number);
	ta_committing = TRUE;
	spin_unlock(&ta_lock);

	rsbac_printk(KERN_INFO "rsbac_list_ta_forget(): removing transaction %u\n",
		     ta_number);

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	srcu_idx2 = srcu_read_lock(&lol_reg_list_srcu);
	list = srcu_dereference(reg_head.head, &reg_list_srcu);
	while (list) {
		if(list->hash_function)
			read_lock(&list->hash_lock);
		nr_hashes = BIT(list->hash_bits);
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&list->hashed[i].lock);
			if (list->hashed[i].ta_copied == ta_number) {
				ta_remove_all_items(list, i);
				list->hashed[i].ta_copied = 0;
			}
			rcu_head_p = get_rcu_free(list, i);
			spin_unlock(&list->hashed[i].lock);
			do_call_rcu(rcu_head_p);
		}
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		list = srcu_dereference(list->next, &reg_list_srcu);
	}
	lol_list = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while (lol_list) {
		if(lol_list->hash_function)
			read_lock(&lol_list->hash_lock);
		nr_hashes = BIT(lol_list->hash_bits);
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&lol_list->hashed[i].lock);
			if (lol_list->hashed[i].ta_copied == ta_number) {
				ta_remove_all_lol_items(lol_list, i);
				lol_list->hashed[i].ta_copied = 0;
			}
			rcu_head_lol_p = get_rcu_free_lol(lol_list, i);
			spin_unlock(&lol_list->hashed[i].lock);
			do_call_rcu_lol(rcu_head_lol_p);
		}
		if(lol_list->hash_function)
			read_unlock(&lol_list->hash_lock);
		lol_list = srcu_dereference(lol_list->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx2);
	srcu_read_unlock(&reg_list_srcu, srcu_idx);

	ta_committing = FALSE;
	wake_up(&ta_wait);

	return 0;
}

int rsbac_list_ta_forget(rsbac_list_ta_number_t ta_number, char *password)
{
	int err;
	struct rsbac_list_ta_data_t ta_data;

	err = rsbac_list_get_data(ta_handle, &ta_number, &ta_data);
	if (err)
		return err;
	if ((RSBAC_UID_NUM(ta_data.commit_uid) != RSBAC_ALL_USERS)
	    && (ta_data.commit_uid != (rsbac_get_vset(),__kuid_val(current_uid())))
	    )
		return -EPERM;
	if (ta_data.password[0]) {
		if (!password)
			return -EPERM;
		if (strncmp
		    (ta_data.password, password,
		     RSBAC_LIST_TA_MAX_PASSLEN))
			return -EPERM;
	}
	return do_forget(ta_number);
}

int rsbac_list_ta_begin(rsbac_time_t ttl,
			rsbac_list_ta_number_t * ta_number_p,
			rsbac_uid_t commit_uid,
			char * name, char *password)
{
	int err;
	rsbac_list_ta_number_t ta;
	struct rsbac_list_ta_data_t ta_data;

	if (unlikely(!ta_number_p))
		return -RSBAC_EINVALIDPOINTER;

	while(ta_committing)
		msleep_interruptible(100);
	if (*ta_number_p) {
	 	if (rsbac_list_exist(ta_handle, ta_number_p))
			return -RSBAC_EEXISTS;
		ta = *ta_number_p;
	} else {
#ifdef CONFIG_RSBAC_LIST_TRANS_RANDOM_TA
		get_random_bytes(&ta, sizeof(ta));
#else
		ta = ta_next++;
#endif
		while (!ta || rsbac_list_exist(ta_handle, &ta)
#ifdef CONFIG_RSBAC_RC_LEARN_TA
			|| (ta == CONFIG_RSBAC_RC_LEARN_TA)
#endif
#ifdef CONFIG_RSBAC_AUTH_LEARN_TA
			|| (ta == CONFIG_RSBAC_AUTH_LEARN_TA)
#endif
#ifdef CONFIG_RSBAC_ACL_LEARN_TA
			|| (ta == CONFIG_RSBAC_ACL_LEARN_TA)
#endif
#ifdef CONFIG_RSBAC_CAP_LEARN_TA
			|| (ta == CONFIG_RSBAC_CAP_LEARN_TA)
#endif
			) {
#ifdef CONFIG_RSBAC_LIST_TRANS_RANDOM_TA
			get_random_bytes(&ta, sizeof(ta));
#else
			ta = ta_next++;
#endif
		}
	}
	if (!ttl || (ttl > CONFIG_RSBAC_LIST_TRANS_MAX_TTL))
		ttl = CONFIG_RSBAC_LIST_TRANS_MAX_TTL;

	rsbac_printk(KERN_INFO "rsbac_list_ta_begin(): starting transaction %u with ttl of %us\n",
		     ta, ttl);

	ta_data.start = RSBAC_CURRENT_TIME;
	ta_data.timeout = ta_data.start + ttl;
	ta_data.commit_uid = commit_uid;
	if (name) {
		strncpy(ta_data.name, name,
			RSBAC_LIST_TA_MAX_NAMELEN - 1);
		ta_data.name[RSBAC_LIST_TA_MAX_NAMELEN - 1] = 0;
	} else
		ta_data.name[0] = 0;
	if (password) {
		strncpy(ta_data.password, password,
			RSBAC_LIST_TA_MAX_PASSLEN - 1);
		ta_data.password[RSBAC_LIST_TA_MAX_PASSLEN - 1] = 0;
	} else
		ta_data.password[0] = 0;
	err = rsbac_list_add(ta_handle, &ta, &ta_data);
	if (!err)
		*ta_number_p = ta;
	return err;
}

int rsbac_list_ta_refresh(rsbac_time_t ttl,
			  rsbac_list_ta_number_t ta_number, char *password)
{
	struct rsbac_list_ta_data_t ta_data;
	int err;

	if (!rsbac_list_exist(ta_handle, &ta_number)) {
		return -RSBAC_ENOTFOUND;
	}
	if (!ttl || (ttl > CONFIG_RSBAC_LIST_TRANS_MAX_TTL))
		ttl = CONFIG_RSBAC_LIST_TRANS_MAX_TTL;

	rsbac_printk(KERN_INFO "rsbac_list_ta_refresh(): refreshing transaction %u for %us\n",
		     ta_number, ttl);

	err = rsbac_list_get_data(ta_handle, &ta_number, &ta_data);
	if (err)
		return err;
	if ((RSBAC_UID_NUM(ta_data.commit_uid) != RSBAC_ALL_USERS)
	    && (ta_data.commit_uid != (rsbac_get_vset(),__kuid_val(current_uid())))
	    )
		return -EPERM;
	if (ta_data.password[0]) {
		if (!password)
			return -EPERM;
		if (strncmp
		    (ta_data.password, password,
		     RSBAC_LIST_TA_MAX_PASSLEN))
			return -EPERM;
	}
	ta_data.timeout = RSBAC_CURRENT_TIME + ttl;
	return rsbac_list_add(ta_handle, &ta_number, &ta_data);
}

int rsbac_list_ta_exist(rsbac_list_ta_number_t ta_number)
{
	if (!ta_number)
		return TRUE;
	else
		return rsbac_list_exist(ta_handle, &ta_number);
}
#endif


/********************/
/* List Access      */
/********************/

/* add item */
/* if item for desc exists, the data is updated */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_add_ttl);
#endif
int rsbac_ta_list_add_ttl(rsbac_list_ta_number_t ta_number,
			  rsbac_list_handle_t handle,
			  rsbac_time_t ttl, void *desc, void *data)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_t * rcu_head_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(!list || (list->self != list)))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(list->info.data_size && !data)) {
		return -RSBAC_EINVALIDVALUE;
	}

/*
	rsbac_pr_debug(lists, "adding to list %s.\n", list->name);
*/
	if (ttl && (ttl != RSBAC_LIST_TTL_KEEP)) {
		if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
			ttl = RSBAC_LIST_MAX_AGE_LIMIT;
		ttl += RSBAC_CURRENT_TIME;
	}
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied || ta_number) {
		if (!list->hashed[hash].ta_copied)
			ta_copy(ta_number, list, hash);
		else if (ta_number) {
			if (list->hashed[hash].ta_copied != ta_number) {
				spin_unlock(&list->hashed[hash].lock);
				if(list->hash_function)
					read_unlock(&list->hash_lock);
				return -RSBAC_EBUSY;
			}
		} else
			ta_number = list->hashed[hash].ta_copied;
		item_p = ta_lookup_item_locked(ta_number, list, hash, desc);
		if (item_p) {	/* exists -> update data, if any */
			if (ttl != RSBAC_LIST_TTL_KEEP)
				item_p->max_age = ttl;
			if (data && list->info.data_size) {
				if (list->def_data
				    && !item_p->max_age
				    && !memcmp(list->def_data, data,
					       list->info.data_size)
				    )
					ta_do_remove_item(list, item_p, hash);
				else
					memcpy(((char *) item_p) +
					       sizeof(*item_p) +
					       list->info.desc_size, data,
					       list->info.data_size);
			}
		} else {
			if (ttl == RSBAC_LIST_TTL_KEEP)
				ttl = 0;
			if (!list->def_data
			    || memcmp(list->def_data, data,
				      list->info.data_size)
			    )
				ta_add_item(ta_number, list, hash, ttl, desc,
					    data);
		}
	}
#endif
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (!ta_number)
#endif
	{
		item_p = lookup_item_locked(list, hash, desc);
		if (item_p) {	/* exists -> update data, if any */
			if (ttl != RSBAC_LIST_TTL_KEEP && item_p->max_age != ttl) {
				item_p->max_age = ttl;
				touch(list);
				list->dirty = TRUE;
			}
			if (data && list->info.data_size) {
				if (list->def_data
				    && !item_p->max_age
				    && !memcmp(list->def_data, data,
					       list->info.data_size)
				    ) {
					do_remove_item(list, item_p, hash);
					touch(list);
					list->dirty = TRUE;
				} else {
					if (memcmp(((char *) item_p) +
							sizeof(*item_p) +
							list->info.desc_size, data,
							list->info.data_size)) {
						memcpy(((char *) item_p) +
							sizeof(*item_p) +
							list->info.desc_size, data,
							list->info.data_size);
						touch(list);
						list->dirty = TRUE;
					}
				}
			}
		} else {
			if (ttl == RSBAC_LIST_TTL_KEEP)
				ttl = 0;
			if (!list->def_data
			    || memcmp(list->def_data, data,
				      list->info.data_size)
			    )
				add_item(list, hash, ttl, desc, data);
			touch(list);
			list->dirty = TRUE;
		}
	}
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->write_count++);
#endif
	rcu_head_p = get_rcu_free(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_call_rcu(rcu_head_p);
	return 0;
}

/* add list of lists sublist item */
/* if item for desc exists, the data is updated */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subadd_ttl);
#endif
int rsbac_ta_list_lol_subadd_ttl(rsbac_list_ta_number_t ta_number,
				 rsbac_list_handle_t handle,
				 rsbac_time_t ttl,
				 void *desc, void *subdesc, void *subdata)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !subdesc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(list->info.subdata_size && !subdata)) {
		return -RSBAC_EINVALIDVALUE;
	}

/*
	rsbac_pr_debug(lists, "adding to list %s.\n", list->name);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (!ta_number)
#endif
	{
		sublist = lookup_lol_item_locked(list, hash, desc);
		if (!sublist && (list->flags & RSBAC_LIST_DEF_DATA))
			sublist = add_lol_item(list, hash, 0, desc, list->def_data);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				remove_lol_item(list, hash, desc);
				err = -RSBAC_EINVALIDTARGET;
			} else {
				/* exists -> lookup subitem */
				if (ttl && (ttl != RSBAC_LIST_TTL_KEEP)) {
					if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
						ttl = RSBAC_LIST_MAX_AGE_LIMIT;
					ttl += RSBAC_CURRENT_TIME;
				}
				item_p = lookup_lol_subitem_locked(list, sublist, subdesc);
				if (item_p) {	/* exists -> update data, if any */
					if (ttl != RSBAC_LIST_TTL_KEEP && item_p->max_age != ttl) {
						item_p->max_age = ttl;
						lol_touch(list);
						list->dirty = TRUE;
					}
					if (subdata
					    && list->info.subdata_size) {
						if (list->def_subdata
						    && !item_p->max_age
						    && !memcmp(list->
							       def_subdata,
							       subdata,
							       list->info.
							       subdata_size)
						    ) {
							do_remove_lol_subitem(sublist, item_p);
							rcu_free_lol_sub(list, hash, item_p);
							lol_touch(list);
							list->dirty = TRUE;
						} else {
							if (memcmp(((char *) item_p) + sizeof(*item_p) + list->info.subdesc_size,
								subdata,
								list->info.subdata_size)) {
								memcpy(((char *) item_p) + sizeof(*item_p) + list->info.subdesc_size,
									subdata,
									list->info.subdata_size);
								lol_touch(list);
								list->dirty = TRUE;
							}
						}
					}
				} else {
					if (ttl == RSBAC_LIST_TTL_KEEP)
						ttl = 0;
					if (!list->def_subdata
					    || memcmp(list->def_subdata,
						      subdata,
						      list->info.
						      subdata_size)
					    ) {
						if (!add_lol_subitem(list,
								sublist,
								ttl,
								subdesc,
								subdata)) {
							err = -RSBAC_ECOULDNOTADDITEM;
						} else {
							lol_touch(list);
							list->dirty = TRUE;
						}
					}
				}
			}
		} else {
			err = -RSBAC_EINVALIDTARGET;
			goto out_unlock;
		}
	}
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied || ta_number) {
		if (!list->hashed[hash].ta_copied) {
			if ((err = ta_lol_copy(ta_number, list, hash)))
				goto out_unlock;
		} else if (ta_number) {
			if (list->hashed[hash].ta_copied != ta_number) {
				err = -RSBAC_EBUSY;
				goto out_unlock;
			}
		} else
			ta_number = list->hashed[hash].ta_copied;
		sublist = ta_lookup_lol_item_locked(ta_number, list, hash, desc);
		if (!sublist && (list->flags & RSBAC_LIST_DEF_DATA)
		    )
			sublist =
			    ta_add_lol_item(ta_number, list, hash, 0, desc,
					    list->def_data);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				ta_remove_lol_item(ta_number, list, hash, desc);
				err = -RSBAC_EINVALIDTARGET;
			} else {
				/* exists -> lookup subitem */
				if (ttl && (ttl != RSBAC_LIST_TTL_KEEP)) {
					if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
						ttl =
						    RSBAC_LIST_MAX_AGE_LIMIT;
					ttl += RSBAC_CURRENT_TIME;
				}
				item_p =
				    lookup_lol_subitem_locked(list, sublist,
						       subdesc);
				if (item_p) {	/* exists -> update data, if any */
					if (ttl != RSBAC_LIST_TTL_KEEP)
						item_p->max_age = ttl;
					if (subdata
					    && list->info.subdata_size) {
						if (list->def_subdata
						    && !item_p->max_age
						    && !memcmp(list->
							       def_subdata,
							       subdata,
							       list->info.
							       subdata_size)
						    ) {
							do_remove_lol_subitem
							    (sublist,
							     item_p);
							rcu_free_lol_sub(list, hash, item_p);
						} else
							memcpy(((char *)
								item_p) +
							       sizeof
							       (*item_p) +
							       list->info.
							       subdesc_size,
							       subdata,
							       list->info.
							       subdata_size);
					}
				} else {
					if (ttl == RSBAC_LIST_TTL_KEEP)
						ttl = 0;
					if (!list->def_subdata
					    || memcmp(list->def_subdata,
						      subdata,
						      list->info.
						      subdata_size)
					    )
						add_lol_subitem(list,
								sublist,
								ttl,
								subdesc,
								subdata);
				}
			}
		} else {
			err = -RSBAC_EINVALIDTARGET;
		}
	}
#endif

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->write_count++);
#endif

out_unlock:
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_call_rcu_lol(rcu_head_lol_p);
	return err;
}

/* add list of lists item */
/* if item for desc exists, the data is updated */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_add_ttl);
#endif
int rsbac_ta_list_lol_add_ttl(rsbac_list_ta_number_t ta_number,
			      rsbac_list_handle_t handle,
			      rsbac_time_t ttl, void *desc, void *data)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (ttl && (ttl != RSBAC_LIST_TTL_KEEP)) {
		if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
			ttl = RSBAC_LIST_MAX_AGE_LIMIT;
		ttl += RSBAC_CURRENT_TIME;
	}

	if (list->info.data_size && !data) {
		return -RSBAC_EINVALIDVALUE;
	}

/*
	rsbac_pr_debug(lists, "adding to list %s.\n", list->name);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (!ta_number)
#endif
	{
		item_p = lookup_lol_item_locked(list, hash, desc);
		if (item_p) {	/* exists -> update data, if any */
			if (ttl != RSBAC_LIST_TTL_KEEP && item_p->max_age != ttl) {
				item_p->max_age = ttl;
				lol_touch(list);
				list->dirty = TRUE;
			}
			if (data && list->info.data_size) {
				if (list->def_data
				    && !item_p->max_age
				    && !memcmp(list->def_data, data,
					       list->info.data_size)
				    && !item_p->count) {
					do_remove_lol_item(list, item_p, hash);
					lol_touch(list);
					list->dirty = TRUE;
				} else {
					if (memcmp(((char *) item_p) +
						sizeof(*item_p) +
						list->info.desc_size, data,
						list->info.data_size)) {
						memcpy(((char *) item_p) +
							sizeof(*item_p) +
							list->info.desc_size, data,
							list->info.data_size);
						lol_touch(list);
						list->dirty = TRUE;
					}
				}
			}
		} else {
			if (ttl == RSBAC_LIST_TTL_KEEP)
				ttl = 0;
			if (!list->def_data
			    || memcmp(list->def_data, data,
				      list->info.data_size)
			    ) {
				add_lol_item(list, hash, ttl, desc, data);
				lol_touch(list);
				list->dirty = TRUE;
			}
		}
	}
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied || ta_number) {
		if (!list->hashed[hash].ta_copied)
			ta_lol_copy(ta_number, list, hash);
		else if (ta_number) {
			if (list->hashed[hash].ta_copied != ta_number) {
				rcu_head_lol_p = get_rcu_free_lol(list, hash);
				spin_unlock(&list->hashed[hash].lock);
				if(list->hash_function)
					read_unlock(&list->hash_lock);
				do_call_rcu_lol(rcu_head_lol_p);
				return -RSBAC_EBUSY;
			}
		} else
			ta_number = list->hashed[hash].ta_copied;
		item_p = ta_lookup_lol_item_locked(ta_number, list, hash, desc);
		if (item_p) {	/* exists -> update data, if any */
			if (ttl != RSBAC_LIST_TTL_KEEP)
				item_p->max_age = ttl;
			if (data && list->info.data_size) {
				if (list->def_data
				    && !item_p->max_age
				    && !memcmp(list->def_data, data,
					       list->info.data_size)
				    && !item_p->count)
					ta_do_remove_lol_item(list,
							      item_p,
							      hash);
				else
					memcpy(((char *) item_p) +
					       sizeof(*item_p) +
					       list->info.desc_size, data,
					       list->info.data_size);
			}
		} else {
			if (ttl == RSBAC_LIST_TTL_KEEP)
				ttl = 0;
			if (!list->def_data
			    || memcmp(list->def_data, data,
				      list->info.data_size)
			    )
				ta_add_lol_item(ta_number, list, hash, ttl, desc,
						data);
		}
	}
#endif
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->write_count++);
#endif
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_call_rcu_lol(rcu_head_lol_p);
	return 0;
}

/* remove item */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_remove);
#endif
int rsbac_ta_list_remove(rsbac_list_ta_number_t ta_number,
			 rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_rcu_free_head_t * rcu_head_p;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(!list || (list->self != list)))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing from list %s.\n", list->name);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);

#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied) {
		if (ta_number) {
			if (ta_lookup_item_locked(list->hashed[hash].ta_copied, list, hash, desc)) {
				if (list->hashed[hash].ta_copied != ta_number) {
					spin_unlock(&list->hashed[hash].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
					return -RSBAC_EBUSY;
				} else
					ta_remove_item(ta_number, list, hash,
						       desc);
			}
		} else
			ta_remove_item(list->hashed[hash].ta_copied, list, hash, desc);
	} else {
		if (ta_number && lookup_item_locked(list, hash, desc)) {
			ta_copy(ta_number, list, hash);
			ta_remove_item(ta_number, list, hash, desc);
		}
	}
	if (!ta_number)
#endif
	{
		if (lookup_item_locked(list, hash, desc)) {	/* exists -> remove */
			remove_item(list, hash, desc);
			touch(list);
			list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
			data_race(list->write_count++);
#endif
		}
	}
	rcu_head_p = get_rcu_free(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_sync_rcu(rcu_head_p);
	return 0;
}

/* remove all items */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_remove_all);
#endif
int rsbac_ta_list_remove_all(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle)
{
	struct rsbac_list_reg_item_t *list;
	int i;
	u_int nr_hashes;
	struct rsbac_list_rcu_free_head_t ** rcu_head_pp = NULL;
#ifdef CONFIG_RSBAC_LIST_TRANS
	struct rsbac_list_rcu_free_head_t ** ta_rcu_head_pp = NULL;
#endif

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing all items from list %s.\n", list->name);
*/

	if(list->hash_function)
		read_lock(&list->hash_lock);
	nr_hashes = BIT(list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (!ta_number)
#endif
	{
		rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_pp));
		if (unlikely(!rcu_head_pp)) {
			if(list->hash_function)
				read_unlock(&list->hash_lock);
			return -RSBAC_ENOMEM;
		}
	}
#ifdef CONFIG_RSBAC_LIST_TRANS
	ta_rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*ta_rcu_head_pp));
	if (unlikely(!ta_rcu_head_pp)) {
		if (!ta_number)
			rsbac_kfree(rcu_head_pp);
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		return -RSBAC_ENOMEM;
	}
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number)
		for (i=0; i<nr_hashes; i++)
			if (list->hashed[i].ta_copied && (list->hashed[i].ta_copied != ta_number)) {
				rsbac_kfree(ta_rcu_head_pp);
				if(list->hash_function)
					read_unlock(&list->hash_lock);
				return -RSBAC_EBUSY;
			}

	for (i=0; i<nr_hashes; i++) {
		spin_lock(&list->hashed[i].lock);
		if (list->hashed[i].ta_copied) {
			ta_remove_all_items(list, i);
			if (ta_number && !list->hashed[i].head)
					list->hashed[i].ta_copied = 0;
		} else {
			if (ta_number && list->hashed[i].head) {
				list->hashed[i].ta_head = NULL;
				list->hashed[i].ta_tail = NULL;
				list->hashed[i].ta_curr = NULL;
				list->hashed[i].ta_count = 0;
				list->hashed[i].ta_copied = ta_number;
			}
		}
		ta_rcu_head_pp[i] = get_rcu_free(list, i);
		spin_unlock(&list->hashed[i].lock);
	}
		
	if (!ta_number)
#endif
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&list->hashed[i].lock);
			if (list->hashed[i].head) {
				remove_all_items(list, i);
				touch(list);
				list->dirty = TRUE;
				rcu_head_pp[i] = get_rcu_free(list, i);
			}
			spin_unlock(&list->hashed[i].lock);
		}
	if(list->hash_function)
		read_unlock(&list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->write_count++);
#endif
	synchronize_rcu();
#ifdef CONFIG_RSBAC_LIST_TRANS
	for (i=0; i<nr_hashes; i++)
		rcu_free_do_cleanup(ta_rcu_head_pp[i]);
	rsbac_kfree(ta_rcu_head_pp);
	if (!ta_number)
#endif
	{
		for (i=0; i<nr_hashes; i++)
			rcu_free_do_cleanup(rcu_head_pp[i]);
		rsbac_kfree(rcu_head_pp);
	}
	return 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subremove_count);
#endif
int rsbac_ta_list_lol_subremove_count(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      void *desc, u_long count)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (!count)
		return 0;
	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif


/*
	rsbac_pr_debug(lists, "removing from list of lists %s, device %02u:%02u.\n",
		       list->name, list->major, list->minor);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied) {
		sublist = ta_lookup_lol_item_locked(list->hashed[hash].ta_copied, list, hash, desc);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				ta_do_remove_lol_item(list, sublist, hash);
			} else {
				struct rsbac_list_item_t * subitem_p;

				if (ta_number
				    && (list->hashed[hash].ta_copied != ta_number)) {
					spin_unlock(&list->hashed[hash].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
					return -RSBAC_EBUSY;
				}
				while (sublist->head && (count > 0)) {
					subitem_p = sublist->head;
					do_remove_lol_subitem(sublist,
							      subitem_p);
					rcu_free_lol_sub(list, hash, subitem_p);
					count--;
				}
				if (!sublist->count
				    && ((list->def_data
					 && !memcmp(((char *) sublist) +
						    sizeof(*sublist) +
						    list->info.desc_size,
						    list->def_data,
						    list->info.data_size)
					)
					|| (!list->info.data_size
					    && (list->
						flags &
						RSBAC_LIST_DEF_DATA)
					)
				    )
				    ) {
					ta_do_remove_lol_item(list,
							      sublist,
							      hash);
				}
			}
		}
	} else {
		if (ta_number && lookup_lol_item_locked(list, hash, desc)) {
			ta_lol_copy(ta_number, list, hash);
			ta_remove_lol_item(ta_number, list, hash, desc);
		}
	}
	if (!ta_number)
#endif
	{
		sublist = lookup_lol_item_locked(list, hash, desc);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				do_remove_lol_item(list, sublist, hash);
				lol_touch(list);
				list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
				data_race(list->write_count++);
#endif
			} else {
				struct rsbac_list_item_t * subitem_p;

				while (sublist->head && (count > 0)) {
					subitem_p = sublist->head;
					/* Changes sublist->head */
					do_remove_lol_subitem(sublist,
							      subitem_p);
					rcu_free_lol_sub(list, hash, subitem_p);
					count--;
				}
				lol_touch(list);
				list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
				data_race(list->write_count++);
#endif
				if (!sublist->count
				    && ((list->def_data
					 && !memcmp(((char *) sublist) +
						    sizeof(*sublist) +
						    list->info.desc_size,
						    list->def_data,
						    list->info.data_size)
					)
					|| (!list->info.data_size
					    && (list->
						flags &
						RSBAC_LIST_DEF_DATA)
					)
				    )
				    ) {
					do_remove_lol_item(list, sublist, hash);
				}
			}
		}
	}
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_sync_rcu_lol(rcu_head_lol_p);
	return 0;
}


#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subremove);
#endif
int rsbac_ta_list_lol_subremove(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void *desc, void *subdesc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !subdesc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing from list of lists %s, device %02u:%02u.\n",
		       list->name, list->major, list->minor);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied) {
		sublist = ta_lookup_lol_item_locked(list->hashed[hash].ta_copied, list, hash, desc);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				ta_do_remove_lol_item(list, sublist, hash);
			} else {
				if (ta_number
				    && (list->hashed[hash].ta_copied != ta_number)) {
					spin_unlock(&list->hashed[hash].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
					return -RSBAC_EBUSY;
				}
				if (lookup_lol_subitem_locked
				    (list, sublist, subdesc))
					remove_lol_subitem(list, hash, sublist,
							   subdesc);
				if (!sublist->head
				    &&
				    ((list->def_data
				      && !memcmp(((char *) sublist) +
						 sizeof(*sublist) +
						 list->info.desc_size,
						 list->def_data,
						 list->info.data_size)
				     )
				     || (!list->info.data_size
					 && (list->
					     flags & RSBAC_LIST_DEF_DATA)
				     )
				    )
				    ) {
					ta_do_remove_lol_item(list,
							      sublist,
							      hash);
				}
			}
		}
	} else {
		if (ta_number && lookup_lol_item_locked(list, hash, desc)) {
			ta_lol_copy(ta_number, list, hash);
			ta_remove_lol_item(ta_number, list, hash, desc);
		}
	}
	if (!ta_number)
#endif
	{
		sublist = lookup_lol_item_locked(list, hash, desc);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				do_remove_lol_item(list, sublist, hash);
				lol_touch(list);
				list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
				data_race(list->write_count++);
#endif
			} else {
				if (lookup_lol_subitem_locked(list, sublist, subdesc)) {	/* exists -> remove and set dirty */
					remove_lol_subitem(list, hash, sublist,
							   subdesc);
					lol_touch(list);
					list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
					data_race(list->write_count++);
#endif
				}
				if (!sublist->head
				    && ((list->def_data
					 && !memcmp(((char *) sublist) +
						    sizeof(*sublist) +
						    list->info.desc_size,
						    list->def_data,
						    list->info.data_size)
					)
					|| (!list->info.data_size
					    && (list->
						flags &
						RSBAC_LIST_DEF_DATA)
					)
				    )
				    ) {
					do_remove_lol_item(list, sublist, hash);
					lol_touch(list);
					list->dirty = TRUE;
				}
			}
		}
	}
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_sync_rcu_lol(rcu_head_lol_p);
	return 0;
}

/* remove same subitem from all items */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subremove_from_all);
#endif
int rsbac_ta_list_lol_subremove_from_all(rsbac_list_ta_number_t ta_number,
					 rsbac_list_handle_t handle,
					 void *subdesc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	int i;
	u_int nr_hashes;
	struct rsbac_list_rcu_free_head_lol_t ** rcu_head_pp = NULL;
#ifdef CONFIG_RSBAC_LIST_TRANS
	struct rsbac_list_rcu_free_head_lol_t ** ta_rcu_head_pp = NULL;
#endif

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!subdesc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing from list of lists %s.\n", list->name);
*/
	if(list->hash_function)
		read_lock(&list->hash_lock);
	nr_hashes = BIT(list->hash_bits);
	rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_pp));
	if (unlikely(!rcu_head_pp)) {
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		return -RSBAC_ENOMEM;
	}
#ifdef CONFIG_RSBAC_LIST_TRANS
	ta_rcu_head_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*ta_rcu_head_pp));
	if (unlikely(!ta_rcu_head_pp)) {
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		rsbac_kfree(rcu_head_pp);
		return -RSBAC_ENOMEM;
	}
	for (i=0; i<nr_hashes; i++) {
		spin_lock(&list->hashed[i].lock);
		if (list->hashed[i].ta_copied) {
			if (ta_number && (list->hashed[i].ta_copied != ta_number)) {
				spin_unlock(&list->hashed[i].lock);
				if(list->hash_function)
					read_unlock(&list->hash_lock);
				synchronize_rcu();
				for (i=0; i<nr_hashes; i++)
					rcu_free_do_cleanup_lol(ta_rcu_head_pp[i]);
				rsbac_kfree(rcu_head_pp);
				rsbac_kfree(ta_rcu_head_pp);
				return -RSBAC_EBUSY;
			}
			sublist = list->hashed[i].head;
			while (sublist) {
				remove_lol_subitem(list, i, sublist, subdesc);
				sublist = sublist->next;
			}
		} else {
			if (ta_number) {
				ta_lol_copy(ta_number, list, i);
				sublist = list->hashed[i].head;
				while (sublist) {
					remove_lol_subitem(list, i, sublist, subdesc);
					sublist = sublist->next;
				}
			}
		}
		ta_rcu_head_pp[i] = get_rcu_free_lol(list, i);
		spin_unlock(&list->hashed[i].lock);
	}
	if (!ta_number)
#endif
	{
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&list->hashed[i].lock);
			sublist = list->hashed[i].head;
			while (sublist) {
				if (lookup_lol_subitem_locked(list, sublist, subdesc)) {	/* exists -> remove and set dirty */
					remove_lol_subitem(list, i, sublist, subdesc);
					lol_touch(list);
					list->dirty = TRUE;
				}
				sublist = sublist->next;
			}
			rcu_head_pp[i] = get_rcu_free_lol(list, i);
			spin_unlock(&list->hashed[i].lock);
		}
	}
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	synchronize_rcu();
	for (i=0; i<nr_hashes; i++) {
		rcu_free_do_cleanup_lol(rcu_head_pp[i]);
#ifdef CONFIG_RSBAC_LIST_TRANS
		rcu_free_do_cleanup_lol(ta_rcu_head_pp[i]);
#endif
	}
	rsbac_kfree(rcu_head_pp);
#ifdef CONFIG_RSBAC_LIST_TRANS
	rsbac_kfree(ta_rcu_head_pp);
#endif
#ifdef CONFIG_RSBAC_LIST_STATS
	if (list->dirty)
		data_race(list->write_count++);
#endif
	return 0;
}

/* remove all subitems */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subremove_all);
#endif
int rsbac_ta_list_lol_subremove_all(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing all subitems from list of lists %s.\n",
		       list->name);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied) {
		sublist = ta_lookup_lol_item_locked(list->hashed[hash].ta_copied, list, hash, desc);
		if (sublist) {
			if (sublist->max_age
			    && (sublist->max_age <= RSBAC_CURRENT_TIME)
			    ) {
				ta_do_remove_lol_item(list, sublist, hash);
			} else {
				if (ta_number
				    && (list->hashed[hash].ta_copied != ta_number)) {
					spin_unlock(&list->hashed[hash].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
					return -RSBAC_EBUSY;
				}
				remove_all_lol_subitems(list, hash, sublist);
				if ((list->def_data
				     && !memcmp(((char *) sublist) +
						sizeof(*sublist) +
						list->info.desc_size,
						list->def_data,
						list->info.data_size)
				    )
				    || (!list->info.data_size
					&& (list->
					    flags & RSBAC_LIST_DEF_DATA)
				    )

				    ) {
					ta_do_remove_lol_item(list,
							      sublist,
							      hash);
				}
			}
		}
	} else {
		if (ta_number && lookup_lol_item_locked(list, hash, desc)) {
			ta_lol_copy(ta_number, list, hash);
			sublist = ta_lookup_lol_item_locked(ta_number, list, hash, desc);
			if (sublist)
				remove_all_lol_subitems(list, hash, sublist);
		}
	}
	if (!ta_number)
#endif
	{
		sublist = lookup_lol_item_locked(list, hash, desc);
		if (sublist && sublist->head) {
			remove_all_lol_subitems(list, hash, sublist);
			lol_touch(list);
			list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
			data_race(list->write_count++);
#endif
		}
	}
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_sync_rcu_lol(rcu_head_lol_p);
	return 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_remove);
#endif
int rsbac_ta_list_lol_remove(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_lol_reg_item_t *list;
	u_int hash = 0;
	struct rsbac_list_rcu_free_head_lol_t * rcu_head_lol_p;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing from list of lists %s.\n",
		       list->name);
*/
	if(list->hash_function) {
		read_lock(&list->hash_lock);
		hash = list->hash_function(desc, list->hash_bits);
	}
	spin_lock(&list->hashed[hash].lock);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (list->hashed[hash].ta_copied) {
		if (ta_number) {
			if (ta_lookup_lol_item_locked
			    (list->hashed[hash].ta_copied, list, hash, desc)) {
				if (list->hashed[hash].ta_copied != ta_number) {
					spin_unlock(&list->hashed[hash].lock);
					if(list->hash_function)
						read_unlock(&list->hash_lock);
					return -RSBAC_EBUSY;
				} else
					ta_remove_lol_item(ta_number, list, hash,
							   desc);
			}
		} else
			ta_remove_lol_item(list->hashed[hash].ta_copied, list, hash, desc);
	} else {
		if (ta_number && lookup_lol_item_locked(list, hash, desc)) {
			ta_lol_copy(ta_number, list, hash);
			ta_remove_lol_item(ta_number, list, hash, desc);
		}
	}
	if (!ta_number)
#endif
	{
		if (lookup_lol_item_locked(list, hash, desc)) {	/* exists -> remove */
			remove_lol_item(list, hash, desc);
			lol_touch(list);
			list->dirty = TRUE;
#ifdef CONFIG_RSBAC_LIST_STATS
			data_race(list->write_count++);
#endif
		}
	}
	rcu_head_lol_p = get_rcu_free_lol(list, hash);
	spin_unlock(&list->hashed[hash].lock);
	if(list->hash_function)
		read_unlock(&list->hash_lock);
	do_sync_rcu_lol(rcu_head_lol_p);
	return 0;
}

/* remove all items */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_remove_all);
#endif
int rsbac_ta_list_lol_remove_all(rsbac_list_ta_number_t ta_number,
				 rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;
	int i;
	u_int nr_hashes;
	struct rsbac_list_rcu_free_head_lol_t ** rcu_head_lol_pp = NULL;
#ifdef CONFIG_RSBAC_LIST_TRANS
	struct rsbac_list_rcu_free_head_lol_t ** ta_rcu_head_lol_pp = NULL;
#endif

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "removing all items from list of lists %s.\n",
		       list->name);
*/
	if(list->hash_function)
		read_lock(&list->hash_lock);
	nr_hashes = BIT(list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (!ta_number)
#endif
	{
		rcu_head_lol_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*rcu_head_lol_pp));
		if (unlikely(!rcu_head_lol_pp)) {
			if(list->hash_function)
				read_unlock(&list->hash_lock);
			return -RSBAC_ENOMEM;
		}
	}
#ifdef CONFIG_RSBAC_LIST_TRANS
	ta_rcu_head_lol_pp = rsbac_kmalloc_clear(nr_hashes * sizeof(*ta_rcu_head_lol_pp));
	if (unlikely(!ta_rcu_head_lol_pp)) {
		if(list->hash_function)
			read_unlock(&list->hash_lock);
		if (!ta_number)
			rsbac_kfree(rcu_head_lol_pp);
		return -RSBAC_ENOMEM;
	}
#endif

#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number)
		for (i=0; i<nr_hashes; i++) {
			if (list->hashed[i].ta_copied && (list->hashed[i].ta_copied != ta_number)) {
				if(list->hash_function)
					read_unlock(&list->hash_lock);
				rsbac_kfree(ta_rcu_head_lol_pp);
				return -RSBAC_EBUSY;
			}
		}

	for (i=0; i<nr_hashes; i++) {
		spin_lock(&list->hashed[i].lock);
		if (list->hashed[i].ta_copied) {
			ta_remove_all_lol_items(list, i);
			if (ta_number && !list->hashed[i].head)
				list->hashed[i].ta_copied = 0;
		} else {
			if (ta_number && list->hashed[i].head) {
				list->hashed[i].ta_head = NULL;
				list->hashed[i].ta_tail = NULL;
				list->hashed[i].ta_curr = NULL;
				list->hashed[i].ta_count = 0;
				list->hashed[i].ta_copied = ta_number;
			}
		}
		ta_rcu_head_lol_pp[i] = get_rcu_free_lol(list, i);
		spin_unlock(&list->hashed[i].lock);
	}

	if (!ta_number)
#endif
		for (i=0; i<nr_hashes; i++) {
			spin_lock(&list->hashed[i].lock);
			if (list->hashed[i].head) {
				remove_all_lol_items(list, i);
				lol_touch(list);
				list->dirty = TRUE;
				rcu_head_lol_pp[i] = get_rcu_free_lol(list, i);
			}
			spin_unlock(&list->hashed[i].lock);
		}
	if(list->hash_function)
		read_unlock(&list->hash_lock);
#ifdef CONFIG_RSBAC_LIST_STATS
	if (list->dirty)
		data_race(list->write_count++);
#endif
	synchronize_rcu();
#ifdef CONFIG_RSBAC_LIST_TRANS
	for (i=0; i<nr_hashes; i++)
		rcu_free_do_cleanup_lol(ta_rcu_head_lol_pp[i]);
	rsbac_kfree(ta_rcu_head_lol_pp);
	if (!ta_number)
#endif
	{
		for (i=0; i<nr_hashes; i++)
			rcu_free_do_cleanup_lol(rcu_head_lol_pp[i]);
		rsbac_kfree(rcu_head_lol_pp);
	}
	return 0;
}

/* get item data */
/* Item data is copied - we cannot give a pointer, because item could be
 * removed */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_data_ttl);
#endif
int rsbac_ta_list_get_data_ttl(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       rsbac_time_t * ttl_p,
			       void *desc, void *data)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	struct rsbac_list_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "getting data from list %s.\n",
		       list->name);
*/
	if (unlikely(data && !list->info.data_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}
	rcu_read_lock();
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		item_p = ta_lookup_item(ta_number, list, hashed, hash, desc);
	else
#endif
		item_p = lookup_item(list, hashed, hash, desc);
	if (item_p
	    && (!item_p->max_age || (item_p->max_age > RSBAC_CURRENT_TIME)
	    )
	    ) {			/* exists -> copy data, if any */
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p =
				    item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
		if (data) {
			memcpy(data,
			       ((char *) item_p) + sizeof(*item_p) +
			       list->info.desc_size, list->info.data_size);
		}
	} else {
		if (!list->def_data)
			err = -RSBAC_ENOTFOUND;
		else {
			if (ttl_p)
				*ttl_p = 0;
			if (data)
				memcpy(data,
				       list->def_data,
				       list->info.data_size);
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_max_subdesc);
#endif
int rsbac_ta_list_lol_get_max_subdesc(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      void *desc, void *subdesc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !subdesc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
/*
	rsbac_pr_debug(lists, "getting data from list %s.\n",
		       list->name);
*/

#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist) {		/* exists -> lookup subitem */
		item_p = rcu_dereference(sublist->tail);
		while (item_p
		       && item_p->max_age
		       && (item_p->max_age > RSBAC_CURRENT_TIME)
		    )
			item_p = rcu_dereference(item_p->prev);
		if (item_p)
			memcpy(subdesc, (char *) item_p + sizeof(*item_p),
			       list->info.subdesc_size);
		else {
			memset(subdesc, 0, list->info.subdesc_size);
			err = -RSBAC_ENOTFOUND;
		}
	} else {
		if (!(list->flags & RSBAC_LIST_DEF_DATA))
			err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_subdata_ttl);
#endif
int rsbac_ta_list_lol_get_subdata_ttl(rsbac_list_ta_number_t ta_number,
				      rsbac_list_handle_t handle,
				      rsbac_time_t * ttl_p,
				      void *desc,
				      void *subdesc, void *subdata)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !subdesc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(subdata && !list->info.subdata_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting data from list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist) {		/* exists -> lookup subitem */
		item_p = lookup_lol_subitem(list, sublist, subdesc);
		if (item_p
		    && (!item_p->max_age
			|| (item_p->max_age > RSBAC_CURRENT_TIME)
		    )
		    ) {		/* exists -> copy data, if any */
			if (ttl_p) {
				if (item_p->max_age)
					*ttl_p =
					    item_p->max_age -
					    RSBAC_CURRENT_TIME;
				else
					*ttl_p = 0;
			}
			if (subdata) {
				memcpy(subdata,
				       ((char *) item_p) +
				       sizeof(*item_p) +
				       list->info.subdesc_size,
				       list->info.subdata_size);
			}
		} else {
			if (!list->def_subdata)
				err = -RSBAC_ENOTFOUND;
			else {
				if (ttl_p)
					*ttl_p = 0;
				if (subdata)
					memcpy(subdata,
					       list->def_subdata,
					       list->info.subdata_size);
			}
		}
	} else {
		if (!list->def_subdata)
			err = -RSBAC_ENOTFOUND;
		else {
			if (ttl_p)
				*ttl_p = 0;
			if (subdata)
				memcpy(subdata,
				       list->def_subdata,
				       list->info.subdata_size);
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_data_ttl);
#endif
int rsbac_ta_list_lol_get_data_ttl(rsbac_list_ta_number_t ta_number,
				   rsbac_list_handle_t handle,
				   rsbac_time_t * ttl_p,
				   void *desc, void *data)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	int err = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(data && !list->info.data_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting data from list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		item_p = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		item_p = lookup_lol_item(list, hashed, hash, desc);
	if (item_p
	    && (!item_p->max_age || (item_p->max_age > RSBAC_CURRENT_TIME)
	    )
	    ) {			/* exists -> copy data, if any */
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p =
				    item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
		if (data) {
			memcpy(data,
			       ((char *) item_p) + sizeof(*item_p) +
			       list->info.desc_size, list->info.data_size);
		}
	} else {
		if (!list->def_data)
			err = -RSBAC_ENOTFOUND;
		else {
			if (ttl_p)
				*ttl_p = 0;
			if (data)
				memcpy(data,
				       list->def_data,
				       list->info.data_size);
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_max_desc);
#endif
int rsbac_ta_list_get_max_desc(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p = NULL;
	struct rsbac_list_item_t *tmp_item_p;
	int err = 0;
	int i;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			tmp_item_p = rcu_dereference(hashed[i].ta_tail);
		else
#endif
			tmp_item_p = rcu_dereference(hashed[i].tail);
		while (tmp_item_p
		       && tmp_item_p->max_age && (tmp_item_p->max_age > RSBAC_CURRENT_TIME)
		    )
			tmp_item_p = rcu_dereference(tmp_item_p->prev);
		if(tmp_item_p) {
			if(list->compare) {
				if(!item_p || list->compare(&tmp_item_p[1], &item_p[1]) > 0)
					item_p = tmp_item_p;
			} else {
				if(!item_p || memcmp(&tmp_item_p[1], &item_p[1], list->info.desc_size) > 0)
					item_p = tmp_item_p;
			}
		}
	}
	if (item_p)
		memcpy(desc, (char *) item_p + sizeof(*item_p),
		       list->info.desc_size);
	else {
		memset(desc, 0, list->info.desc_size);
		err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_next_desc);
#endif
int rsbac_ta_list_get_next_desc(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle,
				void *old_desc, void *next_desc)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!next_desc))
		return -RSBAC_EINVALIDPOINTER;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	if (old_desc) {
		if(list->hash_function)
			hash = list->hash_function(old_desc, list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = ta_lookup_item(ta_number, list, hashed, hash, old_desc);
		else
#endif
			item_p = lookup_item(list, hashed, hash, old_desc);
		if(item_p) {
			item_p = rcu_dereference(item_p->next);
			while (item_p
			       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
			    ) {
				item_p = rcu_dereference(item_p->next);
			}
			hash++;
		} else
			hash = 0;
	} else
		item_p = NULL;
	while (!item_p && (hash < nr_hashes)) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[hash].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[hash].head);
		while (item_p
		       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
		    ) {
			item_p = rcu_dereference(item_p->next);
		}
		hash++;
	}
	if (item_p) {
		memcpy(next_desc, (char *) item_p + sizeof(*item_p),
		       list->info.desc_size);
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	if (item_p)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_next_desc_selector);
#endif
int rsbac_ta_list_get_next_desc_selector(
		rsbac_list_ta_number_t ta_number,
		rsbac_list_handle_t handle,
		void *old_desc,
		void *next_desc,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!next_desc))
		return -RSBAC_EINVALIDPOINTER;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	if (old_desc) {
		if(list->hash_function)
			hash = list->hash_function(old_desc, list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = ta_lookup_item(ta_number, list, hashed, hash, old_desc);
		else
#endif
			item_p = lookup_item(list, hashed, hash, old_desc);
		if(item_p) {
			item_p = rcu_dereference(item_p->next);
			while (item_p
			       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
			       && !selector((char *) item_p + sizeof(*item_p), param)
			    ) {
				item_p = rcu_dereference(item_p->next);
			}
			hash++;
		} else
			hash = 0;
	} else
		item_p = NULL;
	while (!item_p && (hash < nr_hashes)) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[hash].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[hash].head);
		while (item_p
		       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
		       && !selector((char *) item_p + sizeof(*item_p), param)
		    ) {
			item_p = rcu_dereference(item_p->next);
		}
		hash++;
	}
	if (item_p) {
		memcpy(next_desc, (char *) item_p + sizeof(*item_p),
		       list->info.desc_size);
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	if (item_p)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_next_desc);
#endif
int rsbac_ta_list_lol_get_next_desc(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void *old_desc, void *next_desc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!next_desc))
		return -RSBAC_EINVALIDPOINTER;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	if (old_desc) {
		if(list->hash_function)
			hash = list->hash_function(old_desc, list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = ta_lookup_lol_item(ta_number, list, hashed, hash, old_desc);
		else
#endif
			item_p = lookup_lol_item(list, hashed, hash, old_desc);
		if(item_p) {
			item_p = rcu_dereference(item_p->next);
			while (item_p
			       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
			    ) {
				item_p = rcu_dereference(item_p->next);
			}
			hash++;
		} else
			hash = 0;
	} else
		item_p = NULL;
	while (!item_p && (hash < nr_hashes)) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[hash].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[hash].head);
		while (item_p
		       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
		    ) {
			item_p = rcu_dereference(item_p->next);
		}
		hash++;
	}
	if (item_p) {
		memcpy(next_desc, (char *) item_p + sizeof(*item_p),
		       list->info.desc_size);
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	if (item_p)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_next_desc_selector);
#endif
int rsbac_ta_list_lol_get_next_desc_selector(
		rsbac_list_ta_number_t ta_number,
		rsbac_list_handle_t handle,
		void *old_desc, void *next_desc,
		rsbac_list_desc_selector_function_t selector,
		void * param)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;
	if (unlikely(!next_desc))
		return -RSBAC_EINVALIDPOINTER;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	if (old_desc) {
		if(list->hash_function)
			hash = list->hash_function(old_desc, list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = ta_lookup_lol_item(ta_number, list, hashed, hash, old_desc);
		else
#endif
			item_p = lookup_lol_item(list, hashed, hash, old_desc);
		if(item_p) {
			item_p = rcu_dereference(item_p->next);
			while (item_p
			       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
			       && !selector((char *) item_p + sizeof(*item_p), param)
			    ) {
				item_p = rcu_dereference(item_p->next);
			}
			hash++;
		} else
			hash = 0;
	} else
		item_p = NULL;
	while (!item_p && (hash < nr_hashes)) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[hash].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[hash].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[hash].head);
		while (item_p
		       && item_p->max_age && (item_p->max_age > RSBAC_CURRENT_TIME)
		       && !selector((char *) item_p + sizeof(*item_p), param)
		    ) {
			item_p = rcu_dereference(item_p->next);
		}
		hash++;
	}
	if (item_p) {
		memcpy(next_desc, (char *) item_p + sizeof(*item_p),
		       list->info.desc_size);
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	if (item_p)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

/* get item desc by data */
/* Item desc is copied - we cannot give a pointer, because item could be
 * removed.
 * If no compare function is provided (NULL value), memcmp is used.
 * Note: The data value given here is always used as second parameter to the
 *       compare function, so you can use different types for storage and
 *       lookup.
 */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_desc_ttl);
#endif
int rsbac_ta_list_get_desc_ttl(rsbac_list_ta_number_t ta_number,
			   rsbac_list_handle_t handle,
			   rsbac_time_t * ttl_p,
			   void *desc,
			   void *data,
			   rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	struct rsbac_list_hashed_t * hashed;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !data))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting desc from list %s.\n", list->name);
*/
	if (unlikely(!list->info.data_size)) {
		rcu_read_unlock();
		return -RSBAC_EINVALIDREQUEST;
	}

	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	item_p = ta_lookup_item_data(ta_number, list, hashed, list->hash_bits, data, compare);
#else
	item_p = lookup_item_data(list, hashed, list->hash_bits, data, compare);
#endif
	if (item_p) {		/* exists -> copy desc */
		memcpy(desc,
		       ((char *) item_p) + sizeof(*item_p),
		       list->info.desc_size);
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p = item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
	} else {
		err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_desc_selector_ttl);
#endif
int rsbac_ta_list_get_desc_selector_ttl(
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle,
	rsbac_time_t * ttl_p,
	void *desc,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	int err = 0;
	struct rsbac_list_hashed_t * hashed;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !data))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting desc from list %s.\n", list->name);
*/
	if (unlikely(!list->info.data_size)) {
		rcu_read_unlock();
		return -RSBAC_EINVALIDREQUEST;
	}

	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	item_p = ta_lookup_item_data_selector(ta_number, list,
					hashed, list->hash_bits,
					data, compare,
					selector,
					param);
#else
	item_p = lookup_item_data_selector(list,
					hashed, list->hash_bits,
					data, compare,
					selector,
					param);
#endif
	if (item_p) {		/* exists -> copy desc */
		memcpy(desc,
		       ((char *) item_p) + sizeof(*item_p),
		       list->info.desc_size);
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p = item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
	} else {
		err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_desc_ttl);
#endif
int rsbac_ta_list_lol_get_desc_ttl(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       rsbac_time_t * ttl_p,
			       void *desc,
			       void *data,
			       rsbac_list_data_compare_function_t compare)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	int err = 0;
	struct rsbac_list_lol_hashed_t * hashed;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !data))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(!list->info.data_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting desc from list %s.\n", list->name);
*/
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	item_p = ta_lookup_lol_item_data(ta_number, list, hashed, list->hash_bits, data, compare);
#else
	item_p = lookup_lol_item_data(list, hashed, list->hash_bits, data, compare);
#endif
	if (item_p) {		/* exists -> copy desc */
		memcpy(desc,
		       ((char *) item_p) + sizeof(*item_p),
		       list->info.desc_size);
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p = item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
	} else {
		err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_desc_selector_ttl);
#endif
int rsbac_ta_list_lol_get_desc_selector_ttl(
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle,
	rsbac_time_t * ttl_p,
	void *desc,
	void *data,
	rsbac_list_data_compare_function_t compare,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	int err = 0;
	struct rsbac_list_lol_hashed_t * hashed;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!desc || !data))
		return -RSBAC_EINVALIDVALUE;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(!list->info.data_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "getting desc from list %s.\n", list->name);
*/
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	item_p = ta_lookup_lol_item_data_selector(ta_number,
						list, hashed, list->hash_bits,
						data, compare,
						selector,
						param);
#else
	item_p = lookup_lol_item_data_selector(list, hashed, list->hash_bits,
						data, compare,
						selector,
						param);
#endif
	if (item_p) {		/* exists -> copy desc */
		memcpy(desc,
		       ((char *) item_p) + sizeof(*item_p),
		       list->info.desc_size);
		if (ttl_p) {
			if (item_p->max_age)
				*ttl_p = item_p->max_age - RSBAC_CURRENT_TIME;
			else
				*ttl_p = 0;
		}
	} else {
		err = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return err;
}

/* returns TRUE, if item exists or def_data is defined, FALSE, if not */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_exist);
#endif
int rsbac_ta_list_exist(rsbac_list_ta_number_t ta_number,
			rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	int result;
	struct rsbac_list_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle || !desc))
		return FALSE;
	if (unlikely(!list_initialized))
		return FALSE;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return FALSE;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "testing on list %s.\n", list->name);
*/

	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		item_p = ta_lookup_item(ta_number, list, hashed, hash, desc);
	else
#endif
		item_p = lookup_item(list, hashed, hash, desc);
	if (item_p
	    && (!item_p->max_age || (item_p->max_age > RSBAC_CURRENT_TIME)
	    )
	    ) {			/* exists -> TRUE */
		result = TRUE;
	} else {
		result = FALSE;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

/* does item exist? */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subexist);
#endif
int rsbac_ta_list_lol_subexist(rsbac_list_ta_number_t ta_number,
			       rsbac_list_handle_t handle,
			       void *desc, void *subdesc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	int result;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle || !desc || !subdesc))
		return FALSE;
	if (unlikely(!list_initialized))
		return FALSE;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return FALSE;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "testing on list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist) {		/* exists -> lookup subitem */
		item_p = lookup_lol_subitem(list, sublist, subdesc);
		if (item_p
		    && (!item_p->max_age
			|| (item_p->max_age > RSBAC_CURRENT_TIME)
		    )
		    ) {		/* exists -> TRUE */
			result = TRUE;
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subexist_compare);
#endif
int rsbac_ta_list_lol_subexist_compare(rsbac_list_ta_number_t ta_number,
				       rsbac_list_handle_t handle,
				       void *desc,
				       void *subdesc,
				       rsbac_list_compare_function_t
				       compare)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	int result;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle || !desc || !subdesc))
		return FALSE;
	if (unlikely(!list_initialized))
		return FALSE;
	/* Use standard function, if compare is not provided. */
	if (!compare)
		return rsbac_list_lol_subexist(handle, desc, subdesc);

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return FALSE;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "testing on list %s.\n", list->name);
*/

	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist) {		/* exists -> lookup subitem */
		item_p =
		    lookup_lol_subitem_user_compare(list, sublist, subdesc,
						    compare);
		if (item_p
		    && (!item_p->max_age
			|| (item_p->max_age > RSBAC_CURRENT_TIME)
		    )
		    ) {		/* exists -> TRUE */
			result = TRUE;
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_exist);
#endif
int rsbac_ta_list_lol_exist(rsbac_list_ta_number_t ta_number,
			    rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	int result;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle || !desc))
		return FALSE;
	if (unlikely(!list_initialized))
		return FALSE;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return FALSE;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "testing on list %s.\n", list->name);
*/

	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		item_p = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		item_p = lookup_lol_item(list, hashed, hash, desc);
	if (item_p
	    && (!item_p->max_age || (item_p->max_age > RSBAC_CURRENT_TIME)
	    )
	    ) {			/* exists -> TRUE */
		result = TRUE;
	} else {
		result = FALSE;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

/* count number of elements */
/* returns number of elements or negative error code */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_subcount);
#endif
long rsbac_ta_list_lol_subcount(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle, void *desc)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	long result;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/

	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist) {
		result = sublist->count;
	} else {
		result = -RSBAC_ENOTFOUND;
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_all_subcount);
#endif
long rsbac_ta_list_lol_all_subcount(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	long result = 0;
	int i;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			sublist = rcu_dereference(hashed[i].ta_head);
		else
#endif
			sublist = rcu_dereference(hashed[i].head);
		while (sublist) {
			result += sublist->count;
			sublist = rcu_dereference(sublist->next);
		}
	}
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_count);
#endif
long rsbac_ta_list_lol_count(rsbac_list_ta_number_t ta_number,
			     rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;
	long result = 0;
	int i;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	rcu_read_lock();
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			result += hashed[i].ta_count;
		else
#endif
			result += hashed[i].count;
	}
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_count);
#endif
long rsbac_ta_list_count(rsbac_list_ta_number_t ta_number,
			 rsbac_list_handle_t handle)
{
	struct rsbac_list_reg_item_t *list;
	long result = 0;
	int i;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			result += hashed[i].ta_count;
		else
#endif
			result += hashed[i].count;
	}
	rcu_read_unlock();
	return result;
}

/* Get array of all descriptors */
/* Returns number of elements or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array
   of descs, otherwise *array_p is set to NULL. If *array_p has been set,
   caller must call rsbac_kfree(*array_p) after use! */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_all_desc);
#endif
long rsbac_ta_list_get_all_desc(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle, void **array_p)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	u_long count = 0;
	long result = 0;
	u_int item_size;
	int i;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size;
	if(count > RSBAC_MAX_KMALLOC / item_size)
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_all_desc_selector);
#endif
long rsbac_ta_list_get_all_desc_selector (
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle, void **array_p,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	u_long count = 0;
	long result = 0;
	u_int item_size;
	int i;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p || !selector))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size;
	if(count > RSBAC_MAX_KMALLOC / item_size)
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (   (!item_p->max_age
			        || (item_p->max_age >
				    RSBAC_CURRENT_TIME)
			       )
			    && selector(((char *) item_p) + sizeof(*item_p), param)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_subdesc_ttl);
#endif
long rsbac_ta_list_lol_get_all_subdesc_ttl(rsbac_list_ta_number_t
					   ta_number,
					   rsbac_list_handle_t handle,
					   void *desc, void **array_p,
					   rsbac_time_t ** ttl_array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	rsbac_time_t *ttl_p = NULL;
	u_long offset = 0;
	long result = 0;
	u_long count;
	u_int item_size;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist && sublist->count) {
		item_size = list->info.subdesc_size;
		count = sublist->count;
		if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
			count = RSBAC_MAX_KMALLOC / item_size;
		buffer = rsbac_kmalloc(item_size * count);
		if (buffer) {
			if (ttl_array_p)
				ttl_p =
				    rsbac_kmalloc(sizeof(**ttl_array_p) *
						  sublist->count);
			item_p = rcu_dereference(sublist->head);
			while (item_p && (result < count)) {
				if (!item_p->max_age
				    || (item_p->max_age >
					RSBAC_CURRENT_TIME)
				    ) {
					memcpy(buffer + offset,
					       ((char *) item_p) +
					       sizeof(*item_p), item_size);
					if (ttl_p) {
						if (item_p->max_age)
							ttl_p[result] =
							    item_p->
							    max_age -
							    RSBAC_CURRENT_TIME;
						else
							ttl_p[result] = 0;
					}
					offset += item_size;
					result++;
				}
				item_p = rcu_dereference(item_p->next);
			}
			*array_p = buffer;
			if (ttl_array_p)
				*ttl_array_p = ttl_p;
		} else {
			result = -RSBAC_ENOMEM;
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_desc);
#endif
long rsbac_ta_list_lol_get_all_desc(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void **array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	int i;
	u_long count = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		rsbac_pr_debug(lists, "list %s: could not allocate buffer  for %u items of size %u!\n",
			list->name, count, item_size);
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_desc_selector);
#endif
long rsbac_ta_list_lol_get_all_desc_selector (
	rsbac_list_ta_number_t ta_number,
	rsbac_list_handle_t handle,
	void **array_p,
	rsbac_list_desc_selector_function_t selector,
	void * param)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	int i;
	u_long count = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p || !selector))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		rsbac_pr_debug(lists, "list %s: could not allocate buffer  for %u items of size %u!\n",
			list->name, count, item_size);
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (   (!item_p->max_age
			        || (item_p->max_age >
				    RSBAC_CURRENT_TIME)
			       )
			    && selector(((char *) item_p) + sizeof(*item_p), param)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

/* Get array of all data */
/* Returns number of elements or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array
   of datas, otherwise *array_p is set to NULL. If *array_p has been set,
   caller must call rsbac_kfree(*array_p) after use! */
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_all_data);
#endif
long rsbac_ta_list_get_all_data(rsbac_list_ta_number_t ta_number,
				rsbac_list_handle_t handle, void **array_p)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	u_int item_offset;
	int i;
	u_long count = 0;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	if (unlikely(!list->info.data_size)) {
		rcu_read_unlock();
		return -RSBAC_EINVALIDREQUEST;
	}
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.data_size;
	item_offset = list->info.desc_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p) +
				       item_offset, item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_subdata);
#endif
long rsbac_ta_list_lol_get_all_subdata(rsbac_list_ta_number_t ta_number,
				       rsbac_list_handle_t handle,
				       void *desc, void **array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_long count;
	u_int item_size;
	u_int item_offset;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	if (unlikely(!list->info.subdata_size)) {
		return -RSBAC_EINVALIDREQUEST;
	}

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist && sublist->count) {
		item_size = list->info.subdata_size;
		item_offset = list->info.subdesc_size;
		count = sublist->count;
		if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
			count = RSBAC_MAX_KMALLOC / item_size;
		buffer = rsbac_kmalloc(item_size * count);
		if (buffer) {
			item_p = rcu_dereference(sublist->head);
			while (item_p && (result < count)) {
				if (!item_p->max_age
				    || (item_p->max_age >
					RSBAC_CURRENT_TIME)
				    ) {
					memcpy(buffer + offset,
					       ((char *) item_p) +
					       sizeof(*item_p) +
					       item_offset, item_size);
					offset += item_size;
					result++;
				}
				item_p = rcu_dereference(item_p->next);
			}
			*array_p = buffer;
		} else {
			result = -RSBAC_ENOMEM;
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_data);
#endif
long rsbac_ta_list_lol_get_all_data(rsbac_list_ta_number_t ta_number,
				    rsbac_list_handle_t handle,
				    void **array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	u_int item_offset;
	int i;
	u_long count = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	if (unlikely(!list->info.data_size)) {
		rcu_read_unlock();
		return -RSBAC_EINVALIDREQUEST;
	}
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.data_size;
	item_offset = list->info.desc_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p) +
				       item_offset, item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

/* Get item size */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_get_item_size);
#endif
int rsbac_list_get_item_size(rsbac_list_handle_t handle)
{
	struct rsbac_list_reg_item_t *list;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	return list->info.desc_size + list->info.data_size;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_get_subitem_size);
#endif
int rsbac_list_lol_get_subitem_size(rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	return list->info.subdesc_size + list->info.subdata_size;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_get_item_size);
#endif
int rsbac_list_lol_get_item_size(rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	return list->info.desc_size + list->info.data_size;
}

/* Get array of all items */
/* Returns number of items or negative error code */
/* If return value > 0, *array_p contains a pointer to a rsbac_kmalloc'd array of items,
   where desc and data are placed directly behind each other.
   If *array_p has been set (return value > 0), caller must call rsbac_kfree(*array_p) after use! */

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_get_all_items_ttl);
#endif
long rsbac_ta_list_get_all_items_ttl(rsbac_list_ta_number_t ta_number,
				     rsbac_list_handle_t handle,
				     void **array_p,
				     rsbac_time_t ** ttl_array_p)
{
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	rsbac_time_t *ttl_p = NULL;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	int i;
	u_long count = 0;
	struct rsbac_list_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size + list->info.data_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	if (ttl_array_p) {
		ttl_p = rsbac_kmalloc(sizeof(**ttl_array_p) * count);
		if (!ttl_p) {
			result = -ENOMEM;
			rsbac_kfree(buffer);
			goto out_unlock;
		}
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				if (ttl_p) {
					if (item_p->max_age)
						ttl_p[result] =
						    item_p->max_age - RSBAC_CURRENT_TIME;
					else
						ttl_p[result] = 0;
				}
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;
	if (ttl_array_p)
		*ttl_array_p = ttl_p;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_subitems_ttl);
#endif
long rsbac_ta_list_lol_get_all_subitems_ttl(rsbac_list_ta_number_t
					    ta_number,
					    rsbac_list_handle_t handle,
					    void *desc, void **array_p,
					    rsbac_time_t ** ttl_array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *sublist;
	struct rsbac_list_item_t *item_p;
	char *buffer;
	rsbac_time_t *ttl_p = NULL;
	u_long offset = 0;
	long result = 0;
	u_long count;
	u_int item_size;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int hash = 0;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	if(list->hash_function)
		hash = list->hash_function(desc, list->hash_bits);
	hashed = rcu_dereference(list->hashed);
#ifdef CONFIG_RSBAC_LIST_TRANS
	if (ta_number && (hashed[hash].ta_copied == ta_number))
		sublist = ta_lookup_lol_item(ta_number, list, hashed, hash, desc);
	else
#endif
		sublist = lookup_lol_item(list, hashed, hash, desc);
	if (sublist && sublist->count) {
		count = sublist->count;
		item_size =
		    list->info.subdesc_size + list->info.subdata_size;
		if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
			count = RSBAC_MAX_KMALLOC / item_size;
		buffer = rsbac_kmalloc(item_size * count);
		if (likely(buffer)) {
			if (ttl_array_p)
				ttl_p =
				    rsbac_kmalloc(sizeof(**ttl_array_p) *
						  sublist->count);
			item_p = rcu_dereference(sublist->head);
			while (item_p && (result < count)) {
				if (!item_p->max_age
				    || (item_p->max_age >
					RSBAC_CURRENT_TIME)
				    ) {
					memcpy(buffer + offset,
					       ((char *) item_p) +
					       sizeof(*item_p), item_size);
					if (ttl_p) {
						if (item_p->max_age)
							ttl_p[result] =
							    item_p->
							    max_age -
							    RSBAC_CURRENT_TIME;
						else
							ttl_p[result] = 0;
					}
					offset += item_size;
					result++;
				}
				item_p = rcu_dereference(item_p->next);
			}
			*array_p = buffer;
			if (ttl_array_p)
				*ttl_array_p = ttl_p;
		} else {
			result = -RSBAC_ENOMEM;
		}
	}
	rcu_read_unlock();

#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_ta_list_lol_get_all_items);
#endif
long rsbac_ta_list_lol_get_all_items(rsbac_list_ta_number_t ta_number,
				     rsbac_list_handle_t handle,
				     void **array_p)
{
	struct rsbac_list_lol_reg_item_t *list;
	struct rsbac_list_lol_item_t *item_p;
	char *buffer;
	u_long offset = 0;
	long result = 0;
	u_int item_size;
	int i;
	u_long count = 0;
	struct rsbac_list_lol_hashed_t * hashed;
	u_int nr_hashes;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!array_p))
		return -RSBAC_EINVALIDPOINTER;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;
	*array_p = NULL;

#ifdef CONFIG_RSBAC_LIST_TRANS
	while(ta_committing)
		msleep_interruptible(100);
	if (ta_number && !rsbac_ta_list_exist(0, ta_handle, &ta_number))
		return -RSBAC_EINVALIDTRANSACTION;
#endif

	rcu_read_lock();
/*
	rsbac_pr_debug(lists, "list %s.\n", list->name);
*/
	nr_hashes = BIT(list->hash_bits);
	hashed = rcu_dereference(list->hashed);
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			count += hashed[i].ta_count;
		else
#endif
			count += hashed[i].count;
	}
	if(!count) {
		result = 0;
		goto out_unlock;
	}
	item_size = list->info.desc_size + list->info.data_size;
	if(unlikely(count > RSBAC_MAX_KMALLOC / item_size))
		count = RSBAC_MAX_KMALLOC / item_size;
	buffer = rsbac_kmalloc(item_size * count);
	if (unlikely(!buffer)) {
		result = -ENOMEM;
		goto out_unlock;
	}
	for (i=0; i<nr_hashes; i++) {
#ifdef CONFIG_RSBAC_LIST_TRANS
		if (ta_number && (hashed[i].ta_copied == ta_number))
			item_p = rcu_dereference(hashed[i].ta_head);
		else
#endif
			item_p = rcu_dereference(hashed[i].head);
		while (item_p && (result < count)) {
			if (!item_p->max_age
			    || (item_p->max_age >
				RSBAC_CURRENT_TIME)
			    ) {
				memcpy(buffer + offset,
				       ((char *) item_p) +
				       sizeof(*item_p), item_size);
				offset += item_size;
				result++;
			}
			item_p = rcu_dereference(item_p->next);
		}
	}
	*array_p = buffer;

	rcu_read_unlock();
#ifdef CONFIG_RSBAC_LIST_STATS
	data_race(list->read_count++);
#endif
	return result;

out_unlock:
	rcu_read_unlock();
	return result;
}

/* List hash functions
 *
 * nr_hashes is always 2^n, so we can safely use bit operations
 */


#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_u32);
#endif
u_int rsbac_list_hash_u32(void * desc, __u8 hash_bits)
{
	return hash_32(*((__u32 *) desc), rsbac_min(hash_bits, 32));
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_fd);
#endif
u_int rsbac_list_hash_fd(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_64(*((rsbac_inode_nr_t *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_old_fd);
#endif
u_int rsbac_list_hash_old_fd(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_32(*((rsbac_old_inode_nr_t *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_pid);
#endif
u_int rsbac_list_hash_pid(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_32(*((__u32 *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_uid);
#endif
u_int rsbac_list_hash_uid(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_64(*((rsbac_uid_t *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_gid);
#endif
u_int rsbac_list_hash_gid(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_64(*((rsbac_gid_t *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_ipc);
#endif
u_int rsbac_list_hash_ipc(void * desc, __u8 hash_bits)
{
	if (!hash_bits)
		return 0;
	return hash_long(((struct rsbac_ipc_t *) desc)->id.id_nr, rsbac_min(hash_bits, 32));
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_dev);
#endif
u_int rsbac_list_hash_dev(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_32( ((struct rsbac_dev_desc_t *) desc)->major + ((struct rsbac_dev_desc_t *) desc)->minor,
				rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_nettemp);
#endif
u_int rsbac_list_hash_nettemp(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_32(*((rsbac_net_temp_id_t *) desc), rsbac_min(hash_bits, 32)) : 0;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_hash_netobj);
#endif
u_int rsbac_list_hash_netobj(void * desc, __u8 hash_bits)
{
	return hash_bits ? hash_32(*((__u32 *) desc), rsbac_min(hash_bits, 32)) : 0;
}

static int do_rehash(struct rsbac_list_reg_item_t *list, __u8 new_bits)
{
	struct rsbac_list_hashed_t * old_hashed;
	struct rsbac_list_hashed_t * new_hashed;
	int i;
        struct rsbac_list_item_t *item_p;
        struct rsbac_list_item_t *new_item_p;
        u_int new_hash;
        u_int old_nr;
        u_int new_nr = BIT(new_bits);
        u_int item_size;

	new_hashed = rsbac_kmalloc_clear_unlocked(new_nr*sizeof(struct rsbac_list_hashed_t));
	if(unlikely(!new_hashed)) {
		return -RSBAC_ENOMEM;
	}
	write_lock(&list->hash_lock);
	old_nr = BIT(list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
	for(i=0; i<old_nr; i++)
		if(list->hashed[i].ta_copied) {
			write_unlock(&list->hash_lock);
			rsbac_kfree(new_hashed);
			return -RSBAC_EBUSY;
		}
#endif
	old_hashed = list->hashed;
	item_size = sizeof(*item_p) + list->info.desc_size + list->info.data_size;
	for(i=0; i<old_nr; i++) {
		item_p = old_hashed[i].head;
		while(item_p) {
			if (list->slab)
				new_item_p = rsbac_smalloc(list->slab);
			else
				new_item_p = rsbac_kmalloc(item_size);
			if (!new_item_p)
				goto out_nomem;
			memcpy(new_item_p, item_p, item_size);
			new_hash = list->hash_function(&new_item_p[1], new_bits);
	                new_item_p->next = NULL;
		        if (!new_hashed[new_hash].head) {
		        	new_hashed[new_hash].head = new_item_p;
		                new_hashed[new_hash].tail = new_item_p;
		                new_hashed[new_hash].count = 1;
		                new_item_p->prev = NULL;
		        } else {
		        	new_item_p->prev = new_hashed[new_hash].tail;
		        	new_hashed[new_hash].tail->next = new_item_p;
		        	new_hashed[new_hash].tail = new_item_p;
		        	new_hashed[new_hash].count++;
		        }
			item_p = item_p->next;
		}
	}
	for (i=0; i<new_nr; i++) {
		spin_lock_init(&new_hashed[i].lock);
		lockdep_set_class(&new_hashed[i].lock, &list_lock_class);
	}
	rcu_assign_pointer(list->hashed, new_hashed);
	list->hash_bits = new_bits;
	write_unlock(&list->hash_lock);
	synchronize_rcu();
	for(i=0; i<old_nr; i++) {
		item_p = old_hashed[i].head;
		while(item_p) {
			new_item_p = item_p->next;
			rsbac_sfree(list->slab, item_p);
			item_p = new_item_p;
		}
	}
	rsbac_kfree(old_hashed);
	return 0;

out_nomem:
	write_unlock(&list->hash_lock);
	for(i=0; i<new_nr; i++) {
		item_p = new_hashed[i].head;
		while(item_p) {
			new_item_p = item_p->next;
			rsbac_sfree(list->slab, item_p);
			item_p = new_item_p;
		}
	}
	rsbac_kfree(new_hashed);
	return -RSBAC_ENOMEM;
}

static int do_lol_rehash(struct rsbac_list_lol_reg_item_t *list, __u8 new_bits)
{
	struct rsbac_list_lol_hashed_t * old_hashed;
	struct rsbac_list_lol_hashed_t * new_hashed;
	int i;
        struct rsbac_list_lol_item_t *item_p;
        struct rsbac_list_lol_item_t *new_item_p;
        u_int new_hash;
        u_int old_nr;
        u_int new_nr = BIT(new_bits);
        u_int item_size;

	new_hashed = rsbac_kmalloc_clear_unlocked(new_nr*sizeof(struct rsbac_list_lol_hashed_t));
	if(unlikely(!new_hashed)) {
		return -RSBAC_ENOMEM;
	}
	write_lock(&list->hash_lock);
	old_nr = BIT(list->hash_bits);
#ifdef CONFIG_RSBAC_LIST_TRANS
	for(i=0; i<old_nr; i++)
		if(list->hashed[i].ta_copied) {
			write_unlock(&list->hash_lock);
			rsbac_kfree(new_hashed);
			return -RSBAC_EBUSY;
		}
#endif
	old_hashed = list->hashed;
	item_size = sizeof(*item_p) + list->info.desc_size + list->info.data_size;
	for(i=0; i<old_nr; i++) {
		item_p = old_hashed[i].head;
		while(item_p) {
			if (list->slab)
				new_item_p = rsbac_smalloc(list->slab);
			else
				new_item_p = rsbac_kmalloc(item_size);
			if (!new_item_p)
				goto out_nomem;
			memcpy(new_item_p, item_p, item_size);
			new_hash = list->hash_function(&new_item_p[1], new_bits);
	                new_item_p->next = NULL;
		        if (!new_hashed[new_hash].head) {
		        	new_hashed[new_hash].head = new_item_p;
		                new_hashed[new_hash].tail = new_item_p;
		                new_hashed[new_hash].count = 1;
		                new_item_p->prev = NULL;
		        } else {
		        	new_item_p->prev = new_hashed[new_hash].tail;
		        	new_hashed[new_hash].tail->next = new_item_p;
		        	new_hashed[new_hash].tail = new_item_p;
		        	new_hashed[new_hash].count++;
		        }
			item_p = item_p->next;
		}
	}
	for (i=0; i<new_nr; i++) {
		spin_lock_init(&new_hashed[i].lock);
		lockdep_set_class(&new_hashed[i].lock, &list_lock_class);
	}
	rcu_assign_pointer(list->hashed, new_hashed);
	list->hash_bits = new_bits;
	write_unlock(&list->hash_lock);
	synchronize_rcu();
	for(i=0; i<old_nr; i++) {
		item_p = old_hashed[i].head;
		while(item_p) {
			new_item_p = item_p->next;
			rsbac_sfree(list->slab, item_p);
			item_p = new_item_p;
		}
	}
	rsbac_kfree(old_hashed);
	return 0;

out_nomem:
	write_unlock(&list->hash_lock);
	for(i=0; i<new_nr; i++) {
		item_p = new_hashed[i].head;
		while(item_p) {
			new_item_p = item_p->next;
			rsbac_sfree(list->slab, item_p);
			item_p = new_item_p;
		}
	}
	rsbac_kfree(new_hashed);
	return -RSBAC_ENOMEM;
}

#ifdef CONFIG_RSBAC_AUTO_WRITE
/* Work through all lists and resize, if allowed and necessary */
static int rsbac_list_auto_rehash(rsbac_boolean_t force_rehash)
{
	int i;
	int err;
	struct rsbac_list_reg_item_t *list;
	struct rsbac_list_lol_reg_item_t *lol_list;
	long count;
	u_int nr_rehashed = 0;
	u_int nr_hashes;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&reg_list_srcu);
	list = srcu_dereference(reg_head.head, &reg_list_srcu);
	while(list) {
		if((list->flags & RSBAC_LIST_AUTO_HASH_RESIZE)
		   && (list->hash_bits < rsbac_list_max_hash_bits)) {
			count = 0;
			nr_hashes = BIT(list->hash_bits);
			for (i=0; i<nr_hashes; i++) {
				if (list->hashed[i].count <= list->max_items_per_hash) {
					count += list->hashed[i].count;
				} else {
					rsbac_printk(KERN_WARNING "rsbac_list_auto_rehash(): list %s on device %02u:%02u has an invalid count %u in hash %u, skipping it\n",
							list->name, list->major, list->minor, list->hashed[i].count, i);
					i = -1;
					break;
				}
			}
			if (i == -1) {
				list = list->next;
				continue;
			}
			if(count / BIT(list->hash_bits) > rsbac_list_auto_rehash_trigger) {
				u_int new_bits;

				new_bits = list->hash_bits;
				while((new_bits < rsbac_list_max_hash_bits)
					&& (count / BIT(new_bits) > rsbac_list_auto_rehash_trigger))
					new_bits++;
				if(new_bits > rsbac_list_max_hash_bits)
					new_bits = rsbac_list_max_hash_bits;
#ifdef CONFIG_RSBAC_DEBUG
				if(rsbac_debug_auto)
					rsbac_printk(KERN_DEBUG "rsbac_list_auto_rehash(): changing list %s hash bits on device %02u:%02u from %u to %u, sum of %li items\n",
						list->name, list->major, list->minor, list->hash_bits, new_bits, count);
#endif
				err = do_rehash(list, new_bits);
				if(!err)
					nr_rehashed++;
				else {
					rsbac_printk(KERN_WARNING "rsbac_list_auto_rehash(): changing list %s hash bits on device %02u:%02u from %u to %u failed with error %i\n",
							list->name, list->major, list->minor, list->hash_bits, new_bits, err);
				}
			}
		}
		list = srcu_dereference(list->next, &reg_list_srcu);
	}
	srcu_read_unlock(&reg_list_srcu, srcu_idx);
	srcu_idx = srcu_read_lock(&lol_reg_list_srcu);
	lol_list = srcu_dereference(lol_reg_head.head, &lol_reg_list_srcu);
	while(lol_list) {
		if((lol_list->flags & RSBAC_LIST_AUTO_HASH_RESIZE)
		   && (lol_list->hash_bits < rsbac_list_max_hash_bits)) {
			count = 0;
			nr_hashes = BIT(lol_list->hash_bits);
			for (i=0; i<nr_hashes; i++) {
				if (lol_list->hashed[i].count <= lol_list->max_items_per_hash) {
					count += lol_list->hashed[i].count;
				} else {
					rsbac_printk(KERN_WARNING "rsbac_list_auto_rehash(): list of lists %s on device %02u:%02u has an invalid count %u in hash %u, skipping it\n",
							lol_list->name, lol_list->major, lol_list->minor, lol_list->hashed[i].count, i);
					i = -1;
					break;
				}
			}
			if (i == -1) {
				lol_list = lol_list->next;
				continue;
			}
			if(count / BIT(lol_list->hash_bits) > rsbac_list_auto_rehash_trigger) {
				u_int new_bits;

				new_bits = lol_list->hash_bits;
				while((new_bits < rsbac_list_max_hash_bits)
					&& (count / BIT(new_bits) > rsbac_list_auto_rehash_trigger))
					new_bits++;
				if(new_bits > rsbac_list_max_hash_bits)
					new_bits = rsbac_list_max_hash_bits;
#ifdef CONFIG_RSBAC_DEBUG
				if(rsbac_debug_auto)
					rsbac_printk(KERN_DEBUG "rsbac_list_auto_rehash(): changing list of lists %s hash bits on device %02u:%02u from %u to %u, sum of %li items\n",
						lol_list->name, lol_list->major, lol_list->minor, lol_list->hash_bits, new_bits, count);
#endif
				err = do_lol_rehash(lol_list, new_bits);
				if(!err)
					nr_rehashed++;
				else {
					rsbac_printk(KERN_WARNING "rsbac_list_auto_rehash(): changing list of lists %s hash bits on device %02u:%02u from %u to %u failed with error %i\n",
							lol_list->name, lol_list->major, lol_list->minor, lol_list->hash_bits, new_bits, err);
				}
			}
		}
		lol_list = srcu_dereference(lol_list->next, &lol_reg_list_srcu);
	}
	srcu_read_unlock(&lol_reg_list_srcu, srcu_idx);

#ifdef CONFIG_RSBAC_DEBUG
	if(rsbac_debug_auto && ((nr_rehashed > 0) || force_rehash))
		rsbac_printk(KERN_DEBUG "rsbac_list_auto_rehash(): %u lists rehashed\n",
			nr_rehashed);
#endif
	return nr_rehashed;
}
#endif

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_get_hash_bits);
#endif
int rsbac_list_get_hash_bits(rsbac_list_handle_t handle)
{
	struct rsbac_list_reg_item_t *list;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

	return list->hash_bits;
}

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(rsbac_list_lol_get_hash_bits);
#endif
int rsbac_list_lol_get_hash_bits(rsbac_list_handle_t handle)
{
	struct rsbac_list_lol_reg_item_t *list;

	if (unlikely(!handle))
		return -RSBAC_EINVALIDLIST;
	if (unlikely(!list_initialized))
		return -RSBAC_ENOTINITIALIZED;

	list = (struct rsbac_list_lol_reg_item_t *) handle;
	if (unlikely(list->self != list))
		return -RSBAC_EINVALIDLIST;

	return list->hash_bits;
}
