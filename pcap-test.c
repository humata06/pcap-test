#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <netinet/ether.h>

void packet_handler(const u_char *packet, struct pcap_pkthdr *header) {
    struct libnet_ethernet_hdr *eth_header;
    struct libnet_ipv4_hdr *ip_header;
    struct libnet_tcp_hdr *tcp_header;
    const u_char *payload;
    int ethernet_header_length = 14; // Ethernet header length
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    eth_header = (struct libnet_ethernet_hdr *)(packet);

    // Check if the packet is an IP packet (0x0800)
    if (ntohs(eth_header->ether_type) != 0x0800) {
        return;
    }

    ip_header = (struct libnet_ipv4_hdr *)(packet + ethernet_header_length);
    ip_header_length = ip_header->ip_hl * 4;

    // Check if the packet is a TCP packet (protocol number 6)
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    tcp_header = (struct libnet_tcp_hdr *)(packet + ethernet_header_length + ip_header_length);
    tcp_header_length = tcp_header->th_off * 4;

    payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);

    // Print Ethernet header
    printf("Ethernet Header\n");
    printf("   |-Source MAC Address      : %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("   |-Destination MAC Address : %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Print IP header
    printf("IP Header\n");
    printf("   |-Source IP Address        : %s\n", inet_ntoa(ip_header->ip_src));
    printf("   |-Destination IP Address   : %s\n", inet_ntoa(ip_header->ip_dst));

    // Print TCP header
    printf("TCP Header\n");
    printf("   |-Source Port              : %d\n", ntohs(tcp_header->th_sport));
    printf("   |-Destination Port         : %d\n", ntohs(tcp_header->th_dport));

    // Print payload in hexadecimal (up to 20 bytes)
    printf("Payload (first 20 bytes)\n");
    for (int i = 0; i < payload_length && i < 20; i++) {
        printf(" %02x", payload[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "syntax: pcap-test <interface>\n");
        fprintf(stderr, "sample: pcap-test wlan0\n");
        exit(EXIT_FAILURE);
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Listening on %s...\n", dev);

    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (packet == NULL) {
            continue; // Timeout elapsed
        }

        packet_handler(packet, &header);
    }

    pcap_close(handle);
    return 0;
}

