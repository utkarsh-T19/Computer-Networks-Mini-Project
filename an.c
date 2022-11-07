#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <string.h>

void process_packet(u_char *,const struct pcap_pkthdr * , const u_char *);
void find_retransmissions(const u_char * , int );

int main()
{
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline("smallFlows.pcap", errbuff);
    pcap_loop(handle, -1, process_packet, NULL);
}

void process_packet(u_char *args,const struct pcap_pkthdr * header,const u_char *buffer)
{
    int size = header->len;
    struct ethhdr *eth = (struct ethhdr *)buffer;
    if(eth->h_proto == 8) //Check if IPv4
    {
        struct iphdr *iph = (struct iphdr*)(buffer +sizeof(struct ethhdr));
        if(iph->protocol == 6) //Check if TCP
        {
             find_retransmissions(buffer,size);
        }
    }
}

void find_retransmissions(const u_char * Buffer, int Size)
{
    static struct iphdr  previous_packets[20000];
    static struct tcphdr  previous_tcp[20000];
    static int index = 0;
    static int retransmissions = 0;
    int retransmission = 0;
    
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
    
    // IP header
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    previous_packets[index] = *iph;
    
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // TCP header
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    previous_tcp[index]=*tcph;
    index++;
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    unsigned int segmentlength;
    segmentlength = Size - header_size;
    
    /* First check if a same TCP packet has been received */
    for(int i=1;i<index-1;i++)
    {
        // Check if packet has been resent
        unsigned short temphdrlen;
        temphdrlen = previous_packets[i].ihl*4;
        
        // First check IP header
        if ((previous_packets[i].saddr == iph->saddr) // Same source IP address
            && (previous_packets[i].daddr == iph->daddr) // Same destination Ip address
            && (previous_packets[i].protocol == iph->protocol) //Same protocol
            && (temphdrlen == iphdrlen)) // Same header length
        {
            // Then check TCP header
            if((previous_tcp[i].source == tcph->source) // Same source port
                && (previous_tcp[i].dest == tcph->dest) // Same destination port
                && (previous_tcp[i].th_seq == tcph->th_seq) // Same sequence number
                && (previous_tcp[i].th_ack==tcph->th_ack) // Same acknowledge number
                && (previous_tcp[i].th_win == tcph->th_win) // Same window
                && (previous_tcp[i].th_flags == tcph->th_flags) // Same flags
                && (tcph->syn==1 || tcph->fin==1 ||segmentlength>0)) // Check if SYN or FIN are
            {                                                        // set or if tcp.segment 0
                // At this point the packets are almost identical
                //  Now Check previous communication to check for retransmission
                for(int z=index-1;z>=0;z--)
                {   
                    // Find packets going to the reverse direction
                    if ((previous_packets[z].daddr == iph->saddr) // Swapped IP source addresses
                        && (previous_packets[z].saddr ==iph->daddr) // Same for IP dest addreses
                        && (previous_packets[z].protocol == iph->protocol)) // Same protocol
                    {
                        if((previous_tcp[z].dest==tcph->source) // Swapped ports
                            && (previous_tcp[z].source==tcph->dest)
                            && (previous_tcp[z].th_seq-1 != tcph->th_ack) // Not Keepalive
                            && (tcph->syn==1          // Either SYN is set
                                || tcph->fin==1       // Either FIN is set
                                || (segmentlength>0)) // Either segmentlength >0 
                            && (previous_tcp[z].th_seq>tcph->th_seq) // Next sequence number is 
                                                                     // bigger than the expected 
                            && (previous_tcp[z].ack  != 1))  // Last seen ACK is set
                        {
                            retransmission = 1;
                            retransmissions++;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    if (retransmission == 1)
    {
        printf("\n\n******************IPv4 TCP Packet******************\n"); 
        printf("     | IP Version       : %d\n",(unsigned int)iph->version);
        printf("     | Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
        printf("     | Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
        printf("     | Source Port      : %u\n",  ntohs(tcph->source));
        printf("     | Destination Port : %u\n",  ntohs(tcph->dest));
        printf("     | Protocol         : %d\n",(unsigned int)iph->protocol);
        printf("     | Payload Length   : %d Bytes\n",Size - header_size);
        printf("\nTotal Retransmissions: %d\n",retransmissions);
    }
}