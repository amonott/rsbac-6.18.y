/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2019: Amon Ott */
/* User Management Data structures    */
/* Last modified: 17/Dec/2019         */
/**************************************/

#ifndef __RSBAC_UM_TYPES_H
#define __RSBAC_UM_TYPES_H

//#include <rsbac/types.h>

#define RSBAC_UM_MAX_MAXNUM 1000000

#define RSBAC_UM_USER_LIST_NAME  "um_user"
#define RSBAC_UM_GROUP_LIST_NAME  "um_grp"
#define RSBAC_UM_USER_PWDATA_LIST_NAME  "um_upw"
#define RSBAC_UM_GROUP_PWDATA_LIST_NAME  "um_gpw"
#define RSBAC_UM_USER_PWHISTORY_LIST_NAME "um_pwh"
#define RSBAC_UM_ONETIME_LIST_NAME "um_pwot"
#define RSBAC_UM_UID_CACHE_LIST_NAME "um_uch"
#define RSBAC_UM_GID_CACHE_LIST_NAME "um_gch"
#define RSBAC_UM_OLD_USER_LIST_NAME  "um_u."
#define RSBAC_UM_OLD_GROUP_LIST_NAME  "um_g."

#define RSBAC_UM_NR_USER_LIST_HASH_BITS 3
#define RSBAC_UM_NR_GROUP_LIST_HASH_BITS 3
#define RSBAC_UM_NR_USER_PWDATA_LIST_HASH_BITS 3
#define RSBAC_UM_NR_GROUP_PWDATA_LIST_HASH_BITS 1
#define RSBAC_UM_NR_USER_PWHISTORY_LIST_HASH_BITS 3
#define RSBAC_UM_NR_NAME_CACHE_LIST_HASH_BITS 2

#define RSBAC_UM_USER_LIST_VERSION 3
#define RSBAC_UM_GROUP_LIST_VERSION 3
#define RSBAC_UM_USER_PWDATA_LIST_VERSION 1
#define RSBAC_UM_GROUP_PWDATA_LIST_VERSION 1
#define RSBAC_UM_USER_PWHISTORY_LIST_VERSION 3
#define RSBAC_UM_ONETIME_LIST_VERSION 2
#define RSBAC_UM_NAME_CACHE_LIST_VERSION 1

#define RSBAC_UM_USER_OLD_LIST_VERSION 2
#define RSBAC_UM_USER_OLD_OLD_LIST_VERSION 1
#define RSBAC_UM_GROUP_OLD_LIST_VERSION 2
#define RSBAC_UM_GROUP_OLD_OLD_LIST_VERSION 1
#define RSBAC_UM_USER_PWHISTORY_OLD_LIST_VERSION 2
#define RSBAC_UM_ONETIME_OLD_LIST_VERSION 1

#define RSBAC_UM_USER_LIST_KEY 6363636
#define RSBAC_UM_GROUP_LIST_KEY 9847298
#define RSBAC_UM_USER_PWDATA_LIST_KEY 88546513
#define RSBAC_UM_GROUP_PWDATA_LIST_KEY 88546582
#define RSBAC_UM_USER_PWHISTORY_LIST_KEY 8854687
#define RSBAC_UM_ONETIME_LIST_KEY 63273279
#define RSBAC_UM_UID_CACHE_LIST_KEY 129871376
#define RSBAC_UM_GID_CACHE_LIST_KEY 129876363

#define RSBAC_UM_NAME_LEN 65
#define RSBAC_UM_OLD_NAME_LEN 16
#define RSBAC_UM_PASS_LEN 24
#define RSBAC_UM_FULLNAME_LEN 65
#define RSBAC_UM_OLD_FULLNAME_LEN 30
#define RSBAC_UM_HOMEDIR_LEN 101
#define RSBAC_UM_OLD_HOMEDIR_LEN 50
#define RSBAC_UM_SHELL_LEN 45
#define RSBAC_UM_OLD_SHELL_LEN 24

/* length of password hashes:
   hash type (see include/uapi/linux/hash_info.h) + salt + hash value */

typedef rsbac_enum_t rsbac_um_pw_hash_type_t;
#ifdef CONFIG_RSBAC_UM_HASH_DEF_SHA256
#define RSBAC_UM_PW_HASH_DEFAULT_NAME "sha256"
#define RSBAC_UM_PW_HASH_DEFAULT_NUM HASH_ALGO_SHA256
#else
#define RSBAC_UM_PW_HASH_DEFAULT_NAME "sha1"
#define RSBAC_UM_PW_HASH_DEFAULT_NUM HASH_ALGO_SHA1
#endif
#define RSBAC_UM_PW_HASH_OLD_DEFAULT_NAME "sha1"
#define RSBAC_UM_PW_HASH_OLD_DEFAULT_NUM HASH_ALGO_SHA1
#define RSBAC_UM_PW_HASH_UNKNOWN 255
#define RSBAC_UM_PWDATA_HEADER_LEN (sizeof(rsbac_um_pw_hash_type_t)+sizeof(__u32))
#define RSBAC_UM_MIN_PW_HASH_LEN 20
#define RSBAC_UM_MAX_PW_HASH_LEN 64
#define RSBAC_UM_PWDATA_LEN (RSBAC_UM_PWDATA_HEADER_LEN+RSBAC_UM_MAX_PW_HASH_LEN)
#define RSBAC_UM_ALGO_NAME_LEN 16
#define RSBAC_UM_MAX_PASS_LEN (RSBAC_MAXNAMELEN - RSBAC_UM_ALGO_NAME_LEN)

typedef __s32 rsbac_um_days_t;

#ifdef CONFIG_RSBAC_UM_ONETIME
typedef char rsbac_um_password_t[RSBAC_UM_PWDATA_LEN];
#endif

enum rsbac_um_mod_t { UM_name, UM_pass, UM_fullname, UM_homedir, UM_shell,
	UM_group, UM_lastchange, UM_minchange, UM_maxchange,
	UM_warnchange, UM_inactive, UM_expire, UM_ttl,
	UM_cryptpass, UM_pass_algo, UM_cryptpass_algo, UM_none
};

union rsbac_um_mod_data_t {
	char string[RSBAC_MAXNAMELEN];
	rsbac_gid_num_t group;
	rsbac_um_days_t days;
	rsbac_time_t ttl;
};

#if defined(CONFIG_IA32_EMULATION) || defined(CONFIG_X86_X32)
union rsbac_um_mod_data_ia32_t {
	char string[RSBAC_MAXNAMELEN];
	rsbac_gid_num_t group;
	rsbac_um_days_t days;
	rsbac_time_t ttl;
}__attribute__ ((aligned (4)));
#endif

struct rsbac_um_user_entry_t {
	rsbac_gid_num_t group;
	rsbac_um_days_t lastchange;
	rsbac_um_days_t minchange;
	rsbac_um_days_t maxchange;
	rsbac_um_days_t warnchange;
	rsbac_um_days_t inactive;
	rsbac_um_days_t expire;
	char name[RSBAC_UM_NAME_LEN];
	char pass[RSBAC_UM_PASS_LEN];
	char fullname[RSBAC_UM_FULLNAME_LEN];
	char homedir[RSBAC_UM_HOMEDIR_LEN];
	char shell[RSBAC_UM_SHELL_LEN];
};

struct rsbac_um_old_user_entry_t {
	char name[RSBAC_UM_OLD_NAME_LEN];
	char pass[RSBAC_UM_PASS_LEN];
	char fullname[RSBAC_UM_OLD_FULLNAME_LEN];
	char homedir[RSBAC_UM_OLD_HOMEDIR_LEN];
	char shell[RSBAC_UM_OLD_SHELL_LEN];
	rsbac_gid_num_t group;
	rsbac_um_days_t lastchange;
	rsbac_um_days_t minchange;
	rsbac_um_days_t maxchange;
	rsbac_um_days_t warnchange;
	rsbac_um_days_t inactive;
	rsbac_um_days_t expire;
};

#define DEFAULT_UM_U_ENTRY \
    { \
      65534,  /* group */ \
      100000,  /* lastchange */ \
      0,  /* minchange */ \
      365,  /* maxchange */ \
      10,  /* warnchange */ \
      3,  /* inactive */ \
      100000,   /* expire */ \
      "", /* name */ \
      "", /* pass */ \
      "", /* fullname */ \
      "/home", /* homedir */ \
      "/bin/sh" /* shell */ \
    }

struct rsbac_um_group_entry_t {
	char name[RSBAC_UM_NAME_LEN];
	char pass[RSBAC_UM_PASS_LEN];
};

struct rsbac_um_old_group_entry_t {
	char name[RSBAC_UM_OLD_NAME_LEN];
	char pass[RSBAC_UM_PASS_LEN];
};

#if defined(CONFIG_RSBAC_UM_NAME_CACHE) && defined(CONFIG_RSBAC_UM_VIRTUAL)
struct rsbac_um_name_cache_desc_t {
	char name[RSBAC_UM_NAME_LEN];
	rsbac_um_set_t vset;
};
#endif

#endif
