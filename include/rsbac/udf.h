/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2024: Amon Ott */
/* API:                               */
/* Functions for Access               */
/* Control Information / UDF          */
/* Last modified: 13/Dec/2024         */
/************************************ */

#ifndef __RSBAC_UDF_H
#define __RSBAC_UDF_H

#include <rsbac/types.h>

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_udf(void);
#else
int rsbac_init_udf(void) __init;
#endif

/* Get ttl for new cache items in seconds */
/* This function returns 0, if no cache is available, and the ttl value
   otherwise */
rsbac_time_t rsbac_udf_get_ttl(void);

/* Set ttl for new cache items in seconds */
/* ttl must be positive, values bigger than 10 years in seconds
   (RSBAC_LIST_MAX_AGE_LIMIT in lists.h) are reduced to this limit */
void rsbac_udf_set_ttl(rsbac_time_t ttl);

/* Get ttl for in-progress cache items in seconds */
/* This function returns 0, if no cache is available, and the ttl value
   otherwise */
rsbac_time_t rsbac_udf_get_progress_ttl(void);

/* Set ttl for in-progress cache items in seconds */
/* ttl must be positive, values bigger than 10 years in seconds
   (RSBAC_LIST_MAX_AGE_LIMIT in lists.h) are reduced to this limit */
void rsbac_udf_set_progress_ttl(rsbac_time_t ttl);

/* Flush UDF cache lists */
int rsbac_udf_flush_cache(void);
#endif
