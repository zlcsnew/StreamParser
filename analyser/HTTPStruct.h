#ifndef _HTTPSTRUCT
#define _HTTPSTRUCT
#include"generStruct.h"
#define URI_list_max 300
#define MAX_URI_length 1000
#define MAX_host_length 500
#define MAX_cookie_length 1000
#define MAX_UA_length 1000
struct HTTP_flowInfo{
   struct flowInfo Baseinfo;
   int URL_list_length,status,method_number,has_host,has_cookie,has_ua;
   char URI_list[URI_list_max][MAX_URI_length];
   char HTTP_method[URI_list_max][10];
   char HTTP_host[MAX_host_length];
   char HTTP_cookie[MAX_cookie_length];
   char HTTP_UA[MAX_UA_length];
};
#endif
