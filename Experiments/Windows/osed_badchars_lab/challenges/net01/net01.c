#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "io_helpers.h"
#include "stage_trace.h"
#define NET01_PORT 32101
#define NET01_MAX_PAYLOAD 4096
typedef struct { char magic[4]; uint8_t version, kind; uint16_t length; } net01_header;
static int net01_process_candidate(const uint8_t *candidate, size_t length) {
    char processed[128];
    stage_trace_capture(STAGE_PRE_TRANSFORM,candidate,length);
    strcpy(processed,(const char *)candidate);
    stage_trace_capture(STAGE_POST_TRANSFORM,(const uint8_t *)processed,strlen(processed));
    stage_trace_capture(STAGE_FINAL_DESTINATION,(const uint8_t *)processed,strlen(processed));
    return 0;
}
static int net01_handle_client(SOCKET client) {
    net01_header header; uint8_t receive_buffer[NET01_MAX_PAYLOAD+1]; int status;
    status=common_recv_exact(client,(uint8_t *)&header,sizeof(header),3000);
    if(status!=COMMON_OK || memcmp(header.magic,"BCN1",4)!=0 || header.version!=1 || header.kind!=1 || header.length==0 || header.length>NET01_MAX_PAYLOAD) return 1;
    if(common_recv_exact(client,receive_buffer,header.length,3000)!=COMMON_OK) return 1;
    receive_buffer[header.length]=0; stage_trace_capture(STAGE_INITIAL_INPUT,receive_buffer,header.length);
    return net01_process_candidate(receive_buffer,header.length);
}
int main(int argc,char **argv) {
    SOCKET listener=INVALID_SOCKET,client=INVALID_SOCKET; struct sockaddr_in address; int port=argc==2?atoi(argv[1]):NET01_PORT,result=1;
    if(common_winsock_startup()!=COMMON_OK) return 1; listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(listener==INVALID_SOCKET) goto done;
    memset(&address,0,sizeof(address)); address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons((u_short)port);
    if(bind(listener,(struct sockaddr *)&address,sizeof(address))==SOCKET_ERROR || listen(listener,1)==SOCKET_ERROR) goto done;
    client=accept(listener,NULL,NULL); if(client!=INVALID_SOCKET) result=net01_handle_client(client);
done: if(client!=INVALID_SOCKET) closesocket(client); if(listener!=INVALID_SOCKET) closesocket(listener); common_winsock_cleanup(); return result;
}
