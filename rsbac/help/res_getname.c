/********************************** */
/* Rule Set Based Access Control    */
/* Author and (c) 2019:             */
/*   Amon Ott <ao@rsbac.org>        */
/* Getname functions for RES module */
/* Last modified: 09/Dec/2019       */
/********************************** */

#include <rsbac/getname.h>
#include <rsbac/res_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#include <linux/string.h>

static char res_list[RLIM_NLIMITS+2][11] = {
   "cpu",
   "fsize",
   "data",
   "stack",
   "core",
   "rss",
   "nproc",
   "nofile",
   "memlock",
   "as",
   "locks",
   "sigpending",
   "msgqueue",
   "nice",
   "rtprio",
   "rttime",
   "unknown",
   "unknown" };

/*****************************************/

char * get_res_name(char * name,
                    u_int value)
  {
    if (value > RLIM_NLIMITS)
      value = RLIM_NLIMITS;
    if(name) {
      strcpy(name, res_list[value]);
      return name;
    } else {
      return res_list[value];
    }
  };

int get_res_nr(const char * name)
  {
    int i;
    
    if(!name)
      return(RSBAC_RES_NONE);
    for (i = 0; i <= RSBAC_RES_MAX; i++)
      {
        if (!strcmp(name, res_list[i]))
          {
            return(i);
          }
      }
    return(RSBAC_RES_NONE);
  };
