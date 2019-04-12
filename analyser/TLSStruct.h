#ifndef _TLSStruct
#define _TLSStruct
#include<pcap.h>
#include"generStruct.h"
#define MAX_CERT_LEN 10000
struct TLS_flowInfo{
   struct flowInfo Baseinfo;
   int status;//0bit:client_info,1bit:cert_info
   int ciberNum;
   u_short ciberType[30];
   u_char servername[256];
   //u_char *cert_info[MAX_CERT_LEN];
};

struct SSL_header{
	u_char protro;
        u_char main_version;
        u_char sub_version;
        u_char dataLength[2];
};

struct TLS_HeaderShake{
	u_char Type;
        u_char length[3];
};

struct TLS_HS_HelloClient{
	u_char Version[2];
        u_char Random[32];
        u_char SessionID;
        u_char ciberNum[2];
};

struct ExternsionHeader{
	u_short Type;
	u_short length;
};

struct ServerName{
	u_short listLength;
        u_char nameType;
	u_short nameLength;
};
#endif
