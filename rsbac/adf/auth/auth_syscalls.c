/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Authentification module          */
/* File: rsbac/adf/auth/syscalls.c                   */
/*                                                   */
/* Author and (c) 1999-2024: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 13/Dec/2024                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/error.h>
#include <rsbac/auth.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/adf_main.h>
#include <rsbac/adf_syshelpers.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

int rsbac_auth_add_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_add_p_cap */
    return rsbac_auth_add_to_p_capset(ta_number, pid, cap_type, cap_range, ttl);
  }

int rsbac_auth_remove_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_remove_p_cap */
    return rsbac_auth_remove_from_p_capset(ta_number, pid, cap_type, cap_range);
  }

int rsbac_auth_add_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_add_f_cap */
    return rsbac_auth_add_to_f_capset(ta_number, file, cap_type, cap_range, ttl);
  }

int rsbac_auth_remove_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_remove_f_cap */
    return rsbac_auth_remove_from_f_capset(ta_number, file, cap_type, cap_range);
  }

/* end of rsbac/adf/auth/syscalls.c */
