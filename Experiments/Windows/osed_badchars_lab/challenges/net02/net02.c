#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "io_helpers.h"
#include "stage_trace.h"
#define NET02_PORT 32102
#define NET02_MAX 4096
typedef struct { char magic[4]; uint8_t version,kind; uint16_t length; } net02_header;
typedef struct { uint8_t *candidate; size_t length; } net02_session;
static int net02_process_candidate(net02_session *session) {
    uint8_t *normalized=(uint8_t *)HeapAlloc(GetProcessHeap(),0,session->length+1); size_t i,out=0;
    if(!normalized) return 1;
    stage_trace_capture(STAGE_PRE_TRANSFORM,session->candidate,session->length);
    for(i=0;i<session->length;i++) { uint8_t value=session->candidate[i]; if(value=='|') break; if(value>='a'&&value<='z') value=(uint8_t)(value-32); normalized[out++]=value; }
    normalized[out]=0; stage_trace_capture(STAGE_POST_TRANSFORM,normalized,out); stage_trace_capture(STAGE_FINAL_DESTINATION,normalized,out); HeapFree(GetProcessHeap(),0,normalized); return 0;
}
static int net02_handle_client(SOCKET client) {
    net02_header header; net02_session session; memset(&session,0,sizeof(session));
    if(common_recv_exact(client,(uint8_t *)&header,sizeof(header),3000)!=COMMON_OK || memcmp(header.magic,"BCN2",4)!=0 || header.version!=1 || header.kind!=1 || header.length==0 || header.length>NET02_MAX) return 1;
    session.candidate=(uint8_t *)HeapAlloc(GetProcessHeap(),0,header.length); if(!session.candidate) return 1; session.length=header.length;
    if(common_recv_exact(client,session.candidate,session.length,3000)!=COMMON_OK) { HeapFree(GetProcessHeap(),0,session.candidate); return 1; }
    stage_trace_capture(STAGE_INITIAL_INPUT,session.candidate,session.length); { int result=net02_process_candidate(&session); HeapFree(GetProcessHeap(),0,session.candidate); return result; }
}
int main(int argc,char **argv) { SOCKET listener=INVALID_SOCKET,client=INVALID_SOCKET; struct sockaddr_in a; int port=argc==2?atoi(argv[1]):NET02_PORT,result=1; if(common_winsock_startup()!=COMMON_OK)return 1; listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(listener==INVALID_SOCKET)goto done; memset(&a,0,sizeof(a));a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons((u_short)port);if(bind(listener,(struct sockaddr *)&a,sizeof(a))==SOCKET_ERROR||listen(listener,1)==SOCKET_ERROR)goto done;client=accept(listener,NULL,NULL);if(client!=INVALID_SOCKET)result=net02_handle_client(client);done:if(client!=INVALID_SOCKET)closesocket(client);if(listener!=INVALID_SOCKET)closesocket(listener);common_winsock_cleanup();return result; }
