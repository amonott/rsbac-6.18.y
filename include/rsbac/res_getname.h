/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 2019:             */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for RES module */
/* Last modified: 09/Dec/2019       */
/********************************** */

#ifndef __RSBAC_RES_GETNAME_H
#define __RSBAC_RES_GETNAME_H

#include <rsbac/types.h>

char * get_res_name(char * name,
                    u_int value);
int get_res_nr(const char * name);

#endif
