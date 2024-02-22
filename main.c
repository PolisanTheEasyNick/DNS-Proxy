#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct DNS_HEADER {  // RFC1035 4.1.1
  unsigned short id; // identification number
  unsigned short flags;
  unsigned short qd_count; // number of question entries
  unsigned short an_count; // number of answer entries
  unsigned short ar_count; // number of authority entries
  unsigned short ns_count; // number of resource entries
};

struct DNS_HEADER_FLAGS {
  unsigned short QR : 1; // QUERY, 0 for query, 1 for response
  unsigned short
      op_code : 4; // Operational Code, 0 - standard query, 1 - an inverse
                   // query, 2 - server status request, 3-15 - reserved
  unsigned short AA : 1; // Authorative Answer
  unsigned short TC : 1; // TrunCation
  unsigned short RD : 1; // Recursion Desired
  unsigned short RA : 1; // Recursion Available
  unsigned short Z : 4;  // Reserved for future use. Must be zero.
  unsigned short
      RC : 4; /// Response code, 0 - no err, 1 - format err, 2 - server failure,
              /// 3 - name err, 4 - not impl, 5 - refused
  unsigned short NA;       // is non-authenticated data acceptable?
  unsigned short AnswAuth; //
};

struct DNS_QUERY_FLAGS { // RFC1035 4.1.2
  unsigned short qtype;
  unsigned short qclass;
};

struct DNS_RR_FLAGS { // Resource record format RFC1035 4.1.3
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short rdlength;

  unsigned char *ip; // if type is A (1)
  unsigned char
      packet[65536]; // part of the packet with answers; change size to malloc?
  unsigned int packet_size; // size of the packet with answers
  unsigned int an_count;    // count of answers
};

struct DNS_HEADER_FLAGS parse_header_flags(unsigned short flags) {
  struct DNS_HEADER_FLAGS header_flags;
  header_flags.RC = flags & 0b1111;
  header_flags.NA = flags >> 4 & 0b1;
  header_flags.AnswAuth = flags >> 5 & 0b1;
  header_flags.Z = flags >> 6 & 0b1;
  header_flags.RA = flags >> 7 & 0b1;
  header_flags.RD = flags >> 8 & 0b1;
  header_flags.TC = flags >> 9 & 0b1;
  header_flags.AA = flags >> 10 & 0b1;
  header_flags.op_code = flags >> 11 & 0b1111;
  header_flags.QR = flags >> 15 & 0b1;
  return header_flags;
}

unsigned short flags_to_header(struct DNS_HEADER_FLAGS flags) {
  unsigned short result = 0;
  result |= flags.QR;
  result <<= 4;
  result |= flags.op_code;
  result <<= 1;
  result |= flags.AA;
  result <<= 1;
  result |= flags.TC;
  result <<= 1;
  result |= flags.RD;
  result <<= 1;
  result |= flags.RA;
  result <<= 1;
  result |= flags.Z;
  result <<= 1;
  result |= flags.AnswAuth;
  result <<= 1;
  result |= flags.NA;
  result <<= 4;
  result |= flags.RC;
  return result;
}

unsigned char *build_dns_response(int mode) {}

void change_to_dns_format(char *src, unsigned char *dest) {
  int pos = 0;
  int len = 0;
  strcat(src, ".");
  for (int i = 0; i < (int)strlen(src); ++i) {
    if (src[i] == '.') {
      dest[pos] = i - len;
      ++pos;
      for (; len < i; ++len) {
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
  for (i = 0; i < strlen((const char *)str); ++i) {
    unsigned int len = str[i];
    for (int j = 0; j < len; ++j) {
      str[i] = str[i + 1];
      ++i;
    }
    str[i] = '.';
  }
  str[i - 1] = '\0';
}

struct DNS_RR_FLAGS resolve(const char *query, const char *dns_server) {
  char *input = (char *)malloc((strlen(query) + 1) * sizeof(char));
  char *resolver = (char *)malloc((strlen(dns_server) + 1) * sizeof(char));
  if (query) {
    strcpy(input, query);
  } else {
    printf("Error! Query is NULL.\n");
    struct DNS_RR_FLAGS answer_record;
    return answer_record; // empty?
  }

  if (dns_server) {
    strcpy(resolver, dns_server);
  } else {
    printf("Error! Query is NULL.\n");
    struct DNS_RR_FLAGS answer_record;
    return answer_record; // empty?
  }

  unsigned char packet[65536];
  // building a header for request
  printf("Building a header...\n");
  struct DNS_HEADER *header = (struct DNS_HEADER *)&packet;
  header->id = htons(getpid());

  header->flags = 0;
  header->flags |= 0; // query (0) or response (1)
  header->flags <<= 4;
  header->flags |= 0; // opcode
  header->flags <<= 2;
  header->flags |= 0; // Truncated
  header->flags <<= 1;
  header->flags |= 1; // Recursion Desired
  header->flags <<= 2;
  header->flags |= 0; // Z
  header->flags <<= 6;
  header->flags = htons(header->flags);

  header->qd_count = htons(1); // only 1 question
  header->an_count = 0x0000;
  header->ns_count = 0x0000;
  header->ar_count = 0x0000;

  int packet_size = sizeof(struct DNS_HEADER);

  unsigned char *qname = (unsigned char *)&packet[packet_size];
  change_to_dns_format(input, qname);
  packet_size = packet_size + (strlen((const char *)qname) + 1);

  printf("Adding a query flags...\n");
  struct DNS_QUERY_FLAGS *query_flags =
      (struct DNS_QUERY_FLAGS *)&packet[packet_size];
  query_flags->qclass = htons(0x0001);
  query_flags->qtype = htons(0x0001);
  packet_size = packet_size + sizeof(struct DNS_QUERY_FLAGS);

  // creating socket for connecting to DNS
  printf("Creating socket...\n");
  long sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // udp connection
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(53); // 53 UDP port for DNS
  inet_pton(AF_INET, resolver, &(servaddr.sin_addr));

  // connecting
  printf("Connecting to DNS server...\n");
  connect(sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

  // sending query packet to DNS server
  printf("Sending query packet to DNS server...\n");
  write(sock_fd, (unsigned char *)packet, packet_size);

  // receive response packet from DNS
  printf("Receiving response packet...\n");
  int received_packet_size = read(sock_fd, (unsigned char *)packet, 65536);
  if (received_packet_size <= 0)
    close(sock_fd);
  printf("Packet size: %d\n", received_packet_size);
  // parsing the header from reply
  printf("Parcing Header from reply...\n");
  struct DNS_HEADER response_header;
  response_header.id = 0;
  response_header.id |= packet[1];
  response_header.id <<= 8;
  response_header.id |= packet[0];
  if (response_header.id == header->id) {
    printf("Response header ID is same as request header ID: %d.\n",
           response_header.id);
  } else {
    printf("Response ID and request ID is NOT same: %d and %d!\n",
           response_header.id, header->id);
  }

  printf("Parcing flags from Header reply...\n");
  response_header.flags = 0;
  response_header.flags |= packet[2];
  response_header.flags <<= 8;
  response_header.flags |= packet[3];

  struct DNS_HEADER_FLAGS header_flags =
      parse_header_flags(response_header.flags);
  printf("Reply Header flags: QR: %d\nOpcode: %d\nAuthorative: %d\nTruncated: "
         "%d\nRecursion desired: %d\nRecursion available: %d\nZ: %d\nAnswer "
         "authenticated: %d\nNon-authenticated data: %d\nReply code: %d.\n",
         header_flags.QR, header_flags.op_code, header_flags.AA,
         header_flags.TC, header_flags.RD, header_flags.RA, header_flags.Z,
         header_flags.AnswAuth, header_flags.NA, header_flags.RC);

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

  // parsing QNAME from reply
  printf("Parcing QNAME from reply...\n");
  for (int i = 0; i < response_header.qd_count; i++) {
    int size_of_qname = 1;
    for (int j = 12; packet[j] != 0; j++) {
      size_of_qname++;
    }
    unsigned char qname[size_of_qname];
    unsigned char *qname_ptr = &qname[0];
    for (int j = 12; j < 12 + size_of_qname; j++) {
      *qname_ptr++ = packet[j];
    }
    change_to_dot_format(qname);
    printf("QNAME: %s\n", qname);
  }

  // parsing RRs from reply
  printf("Parcing RRs from reply...\n");
  struct DNS_RR_FLAGS answer_record;
  answer_record.an_count = response_header.an_count;

  answer_record.packet_size = 0;
  for (int i = 12, j = 0; i < received_packet_size; i++) {
    answer_record.packet[j++] = packet[i];
    answer_record.packet_size++;
  }
  return answer_record;
}

void server() {
  // creating socket for hosting DNS
  printf("Creating socket for hosting...\n");
  long sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // udp connection
  if (sock_fd == -1) {
    printf("Socket creation failed.\n");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  server_address.sin_port = htons(53);

  if (bind(sock_fd, (struct sockaddr *)&server_address,
           sizeof(server_address)) == -1) {
    printf("Bind failed.\n");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  printf("Listening on port 53...\n");
  unsigned char packet[65536];
  struct sockaddr_in client_address;
  socklen_t client_addr_len = sizeof(client_address);

  while (1) {
    ssize_t bytes_received =
        recvfrom(sock_fd, packet, 65536, 0, (struct sockaddr *)&client_address,
                 &client_addr_len);
    if (bytes_received == -1) {
      printf("Recvfrom failed.\n");
      close(sock_fd);
      exit(EXIT_FAILURE);
    }

    packet[bytes_received] = '\0';
    printf("Received from %s:%d\n", inet_ntoa(client_address.sin_addr),
           ntohs(client_address.sin_port));

    struct DNS_HEADER request_header;
    request_header.id = 0;
    request_header.id |= packet[1];
    request_header.id <<= 8;
    request_header.id |= packet[0];

    request_header.flags = 0;
    request_header.flags |= packet[2];
    request_header.flags <<= 8;
    request_header.flags |= packet[3];

    struct DNS_HEADER_FLAGS flags = parse_header_flags(request_header.flags);

    request_header.qd_count = 0;
    request_header.qd_count |= packet[4];
    request_header.qd_count <<= 8;
    request_header.qd_count |= packet[5];
    printf("Questions count: %d\n", request_header.qd_count);

    request_header.an_count = 0;
    request_header.an_count |= packet[6];
    request_header.an_count <<= 8;
    request_header.an_count |= packet[7];
    printf("Answers count: %d\n", request_header.an_count);

    request_header.ar_count = 0;
    request_header.ar_count |= packet[8];
    request_header.ar_count <<= 8;
    request_header.ar_count |= packet[9];
    printf("Authority RRs count: %d\n", request_header.ar_count);

    request_header.ns_count = 0;
    request_header.ns_count |= packet[10];
    request_header.ns_count <<= 8;
    request_header.ns_count |= packet[11];
    printf("Additional RRs count: %d\n", request_header.ns_count);

    if (flags.Z == 0)
      printf("Z: is zero, continiuing.\n");
    else {
      printf("Z: Z is 1, package corrupted.\n"); // TODO send refused instead?
    }



    if (flags.QR == 0) {
      printf("QR: Message is query.\n");
      switch (flags.op_code) {
      case 0:
        printf("OPCODE: 0, a standard query\n"); // Send to relay and return IP
        if (request_header.qd_count != 0) {
          int size_of_cname = 1;
          for (int j = 12; packet[j] != 0; j++) {
            size_of_cname++;
          }
          unsigned char cname[size_of_cname];
          unsigned char *cname_ptr = &cname[0];
          for (int j = 12; j < 12 + size_of_cname; j++) {
            *cname_ptr++ = packet[j];
          }
          change_to_dot_format(cname);
          printf("CNAME: %s\n", cname);

          // TODO: Add blacklist checking

          // got CNAME, sending to RELAY
          struct DNS_RR_FLAGS answer_record = resolve(cname, "8.8.8.8");
          printf("IP: %s\n", answer_record.ip);

          free(answer_record.ip);

          // building a response
          request_header.an_count = answer_record.an_count;
          flags.QR = 1; // response
          flags.RA = 1; // recursion is available
          unsigned char *response_packet, *response_packet_start;
          response_packet = malloc(1024);
          memset(response_packet, 0, 1024);
          response_packet_start = response_packet;

          response_packet[0] = request_header.id & 0b11111111;// id
          response_packet[1] = (request_header.id >> 8) & 0b11111111;

          response_packet += 2;

          unsigned short flags_bits = flags_to_header(flags);
          response_packet[0] = (flags_bits >> 8) & 0b11111111;
          response_packet[1] = flags_bits & 0b11111111;
          response_packet += 2;

          response_packet[0] = packet[4]; // questions
          response_packet[1] = packet[5];
          response_packet += 2;

          response_packet[0] = 0; // answers
          response_packet[1] = answer_record.an_count; //What if > 255?
          response_packet += 2;

          response_packet[0] = 0; // authority RRs
          response_packet[1] = 0;
          response_packet += 2;

          response_packet[0] = 0; // additional RRs
          response_packet[1] = 0;
          response_packet += 2;

          for (int j = 0; j < answer_record.packet_size; j++) { // copying answer from relay dns response
            response_packet[0] = answer_record.packet[j];
            response_packet++;
          }
          printf("Sending result\n");
          printf("size: %d\n", (int)(response_packet - response_packet_start));
          ssize_t bytes_sent =
              sendto(sock_fd, response_packet_start,
                     response_packet - response_packet_start, 0,
                     (struct sockaddr *)&client_address, client_addr_len);
          if (bytes_sent == -1) {
            perror("Sendto failed");
          }
        }
        break;
      case 1:
        printf("OPCODE: 1, an inverse query\n");
        break;
      case 2:
        printf("OPCODE: 2, a server status request\n");
        break;
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 11:
      case 12:
      case 13:
      case 14:
      case 15:
        printf("OPCODE: %d, reserved for future use\n", flags.op_code);
        break;
      default:
        break;
      }
    } else {
      printf("QR: Message is response.\n"); // TODO send refused?
    }

    if (flags.TC == 0)
      printf("TC: Message is NOT truncated.\n");
    else
      printf("TC: Message is truncated.\n");

    if (flags.RD == 0)
      printf("RD: Recursion not desired.\n");
    else
      printf("RD: Recursion desired.\n");
  }
}

int main() {
  // resolve("polisan.ddns.net", "8.8.8.8");
  server();
  return 0;
}
