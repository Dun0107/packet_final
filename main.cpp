#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


#pragma pack(push, 1)
struct ether_add
{
    unsigned char mac_add[6];
};

struct ether_header
{
    struct ether_add des_mac;
    struct ether_add src_mac;
    unsigned short eth_type;
    //14bytes
};

struct ip_header
{
    unsigned char ip_header_length : 4;
    unsigned char ip_version : 4;
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
#pragma pack(pop)

int http_length;

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

        if(res == 0){
            continue;
        }
        if(res==-1 || res==-2){
            break;
        }

        int eth_res = print_eth_header(data);

        if (eth_res == 0){
            continue;
        }
        //eth_res = 0x0800 -> ip right

        data += sizeof(ether_header);

        int pro_res = print_ip_header(data);

        if (pro_res == 0){
            continue;
        }
        //protocol = 06 -> tcp right

        struct ip_header *ih;
        ih = (struct ip_header *)data;
        data += ih->ip_header_length *4;

        struct tcphdr *th;
        th = (struct tcphdr *)data;
        print_tcp_header(data);
        data += th->th_off*4;

        print_http_header(data);

    }
}

int print_eth_header(const unsigned char *data){
    struct ether_header *eh;
    eh = (struct ether_header *)data;

    printf("\n");
    printf("\n===========MAC ADDRESS===========\n");
    printf("Src MAC : ");
    for (int i = 0; i <= 5; i++) printf("%02x ", eh->src_mac.mac_add[i]);
    printf("\nDes MAC : ");
    for (int i = 0; i <= 5; i++)printf("%02x ", eh->des_mac.mac_add[i]);
    printf("\n");


    unsigned short ether_type = ntohs(eh->eth_type);

    if (ether_type != 0x0800)
        {
           /* printf("******%X**********",ether_type); */
            printf("IP is wrong!\n");
            return 0;
        }
    return 1;
}

int print_ip_header(const unsigned char *data)
{
    struct ip_header *ih;
    ih = (struct ip_header *)data;

        printf("\n===========IP ADDRESS===========\n");
        printf("Src IP : %s\n",inet_ntoa(ih->ip_src_add));
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
        printf("IP length: %d\n", (ih->ip_header_length *4));
        printf("IP total length: %d\n", ntohs(ih->ip_total_length));
        printf("\n");

        http_length = ntohs(ih->ip_total_length) - (ih->ip_header_length*4);

        if (ih->ip_protocol != 0x06)
           {
               printf("TCP is wrong!\n");
               return 0;
           }

        return 1;
}

void print_tcp_header(const unsigned char *data)
{
    struct tcphdr *th;
    th = (struct tcphdr *)data;
    printf("\n==============PORT===============\n");
    printf("Src Port : %d\n", ntohs(th->source));
    printf("Des Port : %d\n", ntohs(th->dest));
    printf("tcp length : %d\n", th->th_off *4);
    http_length = http_length - (th->th_off*4);
}

void print_http_header(const unsigned char *data)
{
    printf("\n============HTTP DATA============\n");
    printf("http_length: %d\n", http_length);
    int i;
    if (http_length >= 16){
        for(i=0; i<=16; i++){
           printf("%c", data[i]);
       }
    }
    if (http_length < 16){
        for (i=0; i<=http_length; i++){
            printf("%c", data[i]);
        }
    }
}

