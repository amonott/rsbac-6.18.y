/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2024: Amon Ott  */
/* Helper functions for all parts      */
/* Last modified:  29/Jul/2024         */
/************************************* */

#ifndef __RSBAC_HELPER_H
#define __RSBAC_HELPER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/rkmem.h>

char * inttostr(char[], int);

char * ulongtostr(char[], u_long);

/* convert u_long_long to binary string representation for MAC module */
char * u64tostrmac(char[], __u64);

int rsbac_get_vset_num(char * sourcename, rsbac_um_set_t * vset_p);

/* covert u_long_long to binary string representation for ACL module */
char * u64tostracl(char[], __u64);

char * longtostr(char[], long);

#include <asm/uaccess.h>

#ifdef CONFIG_RSBAC_UM_VIRTUAL
rsbac_um_set_t rsbac_get_vset(void);
#else
static inline rsbac_um_set_t rsbac_get_vset(void)
  {
    return 0;
  }
#endif

void rsbac_get_owner(rsbac_uid_t * user_p);

static inline int rsbac_get_user(void * kern_p, void __user * user_p, int size)
  {
    if(kern_p && user_p && (size > 0))
      {
        return copy_from_user(kern_p, user_p, size);
      }
    return 0;
  }


static inline int rsbac_put_user(void * kern_p, void __user * user_p, int size)
  {
    if(kern_p && user_p && (size > 0))
      {
        return copy_to_user(user_p,kern_p,size);
      }
    return 0;
  }

static inline struct filename * rsbac_getname(const char __user * name)
  {
    return getname(name);
  }

static inline void rsbac_putname(struct filename * name)
  {
    putname(name);
  }

static inline int clear_user_buf(char * ubuf, int len)
  {
    return clear_user(ubuf,len);
  }

void rsbac_get_attr_error(char * , enum rsbac_adf_request_t);

void rsbac_ds_get_error(const char * function, enum rsbac_attribute_t attr);
void rsbac_ds_get_error_num(const char * function, enum rsbac_attribute_t attr, int err);
void rsbac_ds_set_error(const char * function, enum rsbac_attribute_t attr);
void rsbac_ds_set_error_num(const char * function, enum rsbac_attribute_t attr, int err);

#ifdef CONFIG_RSBAC_RC
void rsbac_rc_ds_get_error(const char * function, enum rsbac_rc_item_t item);
void rsbac_rc_ds_set_error(const char * function, enum rsbac_rc_item_t item);
#endif

#endif
