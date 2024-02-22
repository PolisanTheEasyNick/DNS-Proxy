#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>


struct DNS_HEADER { //RFC1035 4.1.1
    unsigned short id;       // identification number
    unsigned short flags;
    unsigned short qd_count;  // number of question entries
    unsigned short an_count; // number of answer entries
    unsigned short ar_count; // number of authority entries
    unsigned short ns_count; // number of resource entries


};

struct DNS_QUERY_FLAGS { //RFC1035 4.1.2
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_RR_FLAGS { //Resource record format RFC1035 4.1.3
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
};

void change_to_dns_format(char *src, unsigned char *dest) {
    int pos = 0;
    int len = 0;
    strcat(src, ".");
    for(int i = 0; i < (int)strlen(src); ++i) {
        if(src[i] == '.') {
            dest[pos] = i - len;
            ++pos;
            for(; len < i; ++len) {
                dest[pos] = src[len];
                ++pos;
            }
            len++;
        }
    }
    dest[pos] = '\0';
}

void change_to_dot_format(unsigned char *str) {
    int i;
    for(i = 0; i < strlen((const char*)str); ++i) {
        unsigned int len = str[i];
        for(int j = 0; j < len; ++j) {
            str[i] = str[i + 1];
            ++i;
        }
        str[i] = '.';
    }
    str[i - 1] = '\0';
}



int main()
{
    char input[] = "polisan.ddns.net";
    unsigned char packet[65536];
    //building a header for request
    printf("Building a header...\n");
    struct DNS_HEADER *header = (struct DNS_HEADER*)&packet;
    header->id = htons(getpid());

    header->flags = 0;
    header->flags |= 0; //query
    header->flags <<= 4;
    header->flags |= 0; //opcode
    header->flags <<= 1;
    header->flags |= 0; //Authoritative Answer
    header->flags <<= 1;
    header->flags |= 0; //TC
    header->flags <<= 1;
    header->flags |= 1; //Recursion Desired
    header->flags <<= 1;
    header->flags |= 0; //Recursion Available
    header->flags <<= 3;
    header->flags |= 0; //Z
    header->flags <<= 4;
    header->flags |= 0; //Response code

    header->qd_count = htons(1); //only 1 question
    header->an_count = 0x0000;
    header->ns_count = 0x0000;
    header->ar_count = 0x0000;

    int packet_size = sizeof(struct DNS_HEADER);

    unsigned char *qname = (unsigned char*)&packet[packet_size];
    change_to_dns_format(input, qname);
    packet_size = packet_size + (strlen((const char *)qname) + 1);

    printf("Adding a query flags...\n");
    struct DNS_QUERY_FLAGS *query_flags = (struct DNS_QUERY_FLAGS*) &packet[packet_size];
    query_flags->qclass = htons(0x0001);
    query_flags->qtype = htons(0x0001);
    packet_size = packet_size + sizeof(struct DNS_QUERY_FLAGS);

    //creating socket for connecting to DNS
    printf("Creating socket...\n");
    long sock_fd = socket(AF_INET, SOCK_DGRAM, 0); //udp connection
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53); //53 UDP port for DNS
    inet_pton(AF_INET, "208.67.222.220", &(servaddr.sin_addr)); //OpenDNS dns server

    //connecting
    printf("Connecting to OpenDNS server...\n");
    connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

    //sending query packet to DNS server
    printf("Sending query packet to DNS server...\n");
    write(sock_fd, (unsigned char *)packet, packet_size);

    //receive response packet from DNS
    printf("Receiving response packet...\n");
    if(read(sock_fd, (unsigned char*)packet, 65536) <= 0)
        close(sock_fd);

    //parsing the header from reply
    printf("Parcing Header from reply...\n");
    struct DNS_HEADER response_header;
    response_header.id = 0;
    response_header.id |= packet[1]; //remember about network byte order
    response_header.id <<= 8;
    response_header.id |= packet[0];
    if(response_header.id == header->id) {
        printf("Response header ID is same as request header ID: %d.\n", response_header.id);
    } else {
        printf("Response ID and request ID is NOT same: %d and %d!\n", response_header.id, header->id);
    }

    printf("Parcing flags from Header reply...\n");
    response_header.flags = 0;
    response_header.flags |= packet[2];
    response_header.flags <<= 8;
    response_header.flags |= packet[3];
    unsigned short RC = response_header.flags & 0b1111;
    unsigned short NA = response_header.flags >> 4 & 0b1;
    unsigned short AnswAuth = response_header.flags >> 5 & 0b1;
    unsigned short Z = response_header.flags >> 6 & 0b1;
    unsigned short RA = response_header.flags >> 7 & 0b1;
    unsigned short RD = response_header.flags >> 8 & 0b1;
    unsigned short TC = response_header.flags >> 9 & 0b1;
    unsigned short AA = response_header.flags >> 10 & 0b1;
    unsigned short op_code = response_header.flags >> 11 & 0b1111;
    unsigned short QR = response_header.flags >> 15 & 0b1;
    printf("Reply Header flags: QR: %d\nOpcode: %d\nAuthorative: %d\nTruncated: %d\nRecursion desired: %d\nRecursion available: %d\nZ: %d\nAnswer authenticated: %d\nNon-authenticated data: %d\nReply code: %d.\n", QR, op_code, AA, TC, RD, RA, Z, AnswAuth, NA, RC);

    response_header.qd_count = 0;
    response_header.qd_count |= packet[4];
    response_header.qd_count <<= 8;
    response_header.qd_count |= packet[5];
    printf("Questions count: %d\n", response_header.qd_count);

    response_header.an_count = 0;
    response_header.an_count |= packet[6];
    response_header.an_count <<= 8;
    response_header.an_count |= packet[7];
    printf("Answers count: %d\n", response_header.an_count);

    response_header.ar_count = 0;
    response_header.ar_count |= packet[8];
    response_header.ar_count <<= 8;
    response_header.ar_count |= packet[9];
    printf("Authority RRs count: %d\n", response_header.ar_count);

    response_header.ns_count = 0;
    response_header.ns_count |= packet[10];
    response_header.ns_count <<= 8;
    response_header.ns_count |= packet[11];
    printf("Additional RRs count: %d\n", response_header.ns_count);

    //parsing QNAME from reply
    printf("Parcing QNAME from reply...\n");
    for(int i = 0; i < response_header.qd_count; i++) {
        int size_of_qname = 1;
        for(int j = 12; packet[j] != 0; j++) {
            size_of_qname++;
        }
        unsigned char qname[size_of_qname];
        unsigned char *qname_ptr = &qname[0];
        for(int j = 12; j < 12+size_of_qname; j++) {
            *qname_ptr++ = packet[j];
        }
        change_to_dot_format(qname);
        printf("QNAME: %s\n", qname);

    }

    //parsing RRs from reply
    printf("Parcing RRs from reply...\n");
    for(int i = 0; i < response_header.an_count; i++) {
        struct DNS_RR_FLAGS answer_record;
        int pos_of_0c = 0;
        for(int j = 12; packet[j] != 0x0c; j++) {
            pos_of_0c = j;
        }
        pos_of_0c++;
        pos_of_0c++;
        answer_record.type = 0;
        answer_record.type |= packet[pos_of_0c++];
        answer_record.type <<= 8;
        answer_record.type |= packet[pos_of_0c++];
        printf("Type: %d\n", answer_record.type);

        answer_record.class = 0;
        answer_record.class |= packet[pos_of_0c++];
        answer_record.class <<= 8;
        answer_record.class |= packet[pos_of_0c++];
        printf("Class: %d\n", answer_record.class);

        answer_record.ttl = 0;
        answer_record.ttl |= packet[pos_of_0c++];
        answer_record.ttl <<= 8;
        answer_record.ttl |= packet[pos_of_0c++];
        answer_record.ttl <<= 8;
        answer_record.ttl |= packet[pos_of_0c++];
        answer_record.ttl <<= 8;
        answer_record.ttl |= packet[pos_of_0c++];
        printf("TTL: %d\n", answer_record.ttl);

        answer_record.rdlength = 0;
        answer_record.rdlength |= packet[pos_of_0c++];
        answer_record.rdlength <<= 8;
        answer_record.rdlength |= packet[pos_of_0c++];
        printf("Data length: %d\n", answer_record.rdlength);

        unsigned short data[answer_record.rdlength];
        unsigned char IP[16];
        for(int j = 0; j < answer_record.rdlength; j++) {
            data[j] = packet[pos_of_0c++];
        }
        sprintf(IP, "%d.%d.%d.%d\0", data[0], data[1], data[2], data[3]);
        printf("IP address: %s\n", IP);

    }

    return 0;
}
