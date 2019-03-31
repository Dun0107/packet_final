#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

struct ether_add
{
    unsigned char mac_add[6];
};

struct ether_header
{
    struct ether_add src_mac;
    struct ether_add des_mac;
    unsigned short eth_type;
    //14bytes
};

struct ip_header
{
    unsigned char ip_version : 4;
    unsigned char ip_header_length : 4;
    unsigned char ip_TOS;
    unsigned short ip_total_length;
    unsigned short ip_iden;
    unsigned char flag_x : 1;
    unsigned char flag_D : 1;
    unsigned char flag_M : 1;
    unsigned char offset_part_1 : 5;
    unsigned char offset_part_2;
    unsigned char TTL;
    unsigned char ip_protocol;
    unsigned short chk_sum;
    struct in_addr ip_src_add;
    struct in_addr ip_des_add;
    //20bytes
};

struct tcp_header
{
    unsigned short src_port;
    unsigned short des_port;
    unsigned long sqn_num;
    unsigned long ack_num;
    unsigned char offset : 4;
    unsigned char ns : 1;
    unsigned char reserve : 3;
    unsigned char flag_cwr : 1;
    unsigned char flag_ece : 1;
    unsigned char flag_urgent : 1;
    unsigned char flag_ack : 1;
    unsigned char flag_push : 1;
    unsigned char flag_reset : 1;
    unsigned char flag_syn : 1;
    unsigned char flag_fin : 1;
    unsigned short window;
    unsigned short chk_sum;
    unsigned short urgent_point;
    //20bytes
};

int print_eth_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
void print_tcp_header(const unsigned char *data);
void print_http_header(const unsigned char *data);

int main(int argc,char **argv){
    if (argc!=2) {
        printf("argc error");
        return -1;
    }

    char *dev = argv[1];
    char *errbuf=NULL;
    pcap_t *handle= pcap_open_live(dev,65535,1,1,errbuf);

    while(1){
        struct pcap_pkthdr *header;
        const u_char *data;

        int res = pcap_next_ex(handle,&header,&data);
        printf("%d",res);

        if(res == 0){
            continue;
        }
        if(res==-1 || res==-2){
            break;
        }

        int eth_res = print_eth_header(data);

        printf("%d", eth_res);
        if (eth_res == 0){
            continue;
        }
        //eth_res = 0x0800 -> ip right

        data += 14;

        int pro_res = print_ip_header(data);
        printf("%d", pro_res);
        if (pro_res == 0){
            continue;
        }
        //protocol = 06 -> tcp right

        data += 20;
        print_tcp_header(data);
        data += 20;
        print_http_header(data);
        data += 20;

    }
}

int print_eth_header(const unsigned char *data){
    struct ether_header *eh;
    eh = (struct ether_header *)data;
    unsigned short ether_type = ntohs(eh->eth_type);
    if (ether_type != 0x0800)
        {
           /* printf("******%X**********",ether_type); */
            printf("IP is wrong!\n");
            return 0;
        }
    printf("\n");
    printf("\n===========MAC ADDRESS===========\n");
    printf("Src MAC : ");
    for (int i = 0; i <= 5; i++) printf("%02x ", eh->src_mac.mac_add[i]);
    printf("\nDes MAC : ");
    for (int i = 0; i <= 5; i++)printf("%02x ", eh->des_mac.mac_add[i]);
    printf("\n");
    return 1;
}

int print_ip_header(const unsigned char *data)
{
    struct ip_header *ih;
    ih = (struct ip_header *)data;
    if (ih->ip_protocol != 0x06)
       {
           printf("TCP is wrong!\n");
           return 0;
       }
        printf("\n===========IP ADDRESS===========\n");
        printf("Src IP : %s\n",inet_ntoa(ih->ip_src_add));
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
        printf("\n");

        return 1;
}

void print_tcp_header(const unsigned char *data)
{
    struct tcp_header *th;
    th = (struct tcp_header *)data;
    printf("\n==============PORT===============\n");
    printf("Src Port : %d\n", ntohs(th->src_port));
    printf("Des Port : %d\n", ntohs(th->des_port));
}

void print_http_header(const unsigned char *data)
{
    printf("\n============HTTP DATA============\n");
    int i;
    for(i=0; i<=16; i++){
        printf("%c", data[i]);
    }
}
//    struct ip_header *ih;
//    data = (ih->ip_total_length)*4 - (ih->ip_header_length)*4;
//}
