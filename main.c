#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libconfig.h>
#include <time.h> //for packet id generation

struct config conf;

enum Response {
    NOT_FOUND = 0,
    REFUSED = 1,
    RESOLVE = 2
};

struct config {
    char upstream_ip[16];
    char **blacklist;
    unsigned short blacklist_items;
    enum Response response_type;
    char resolve_ip[16]; //ip address to resolve with if domain blacklisted
};

void load_config(const char *config_file, struct config *conf) {
    config_t cfg;
    config_init(&cfg);

    if (!config_read_file(&cfg, config_file)) {
        fprintf(stderr, "Error reading config file: %s\n", config_error_text(&cfg));
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }

    const char *upstream_ip;
    if (!config_lookup_string(&cfg, "upstream_ip", &upstream_ip)) {
        fprintf(stderr, "Missing upstream_ip in config file\n");
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }
    strncpy(conf->upstream_ip, upstream_ip, sizeof(conf->upstream_ip));

    const config_setting_t *blacklist = config_lookup(&cfg, "blacklist");
    int num_blacklist = config_setting_length(blacklist);
    conf->blacklist = malloc(num_blacklist * 253 * sizeof(char *));
    if (conf->blacklist == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }
    conf->blacklist_items = num_blacklist;
    printf("Num blacklist: %d\n", num_blacklist);
    for (int i = 0; i < num_blacklist; i++) {
        const char *domain = config_setting_get_string_elem(blacklist, i);
        conf->blacklist[i] = strdup(domain);
    }

    const char *response_type;
    if (!config_lookup_string(&cfg, "response_type", &response_type)) {
        fprintf(stderr, "Missing response_type in config file\n");
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }
    if (strcmp(response_type, "NOT_FOUND") == 0) {
        conf->response_type = NOT_FOUND;
    } else if (strcmp(response_type, "REFUSED") == 0) {
        conf->response_type = REFUSED;
    } else if (strcmp(response_type, "RESOLVE") == 0) {
        conf->response_type = RESOLVE;
        const char *resolve_ip;
        if (!config_lookup_string(&cfg, "resolve_ip", &resolve_ip)) {
            fprintf(stderr, "Missing resolve_ip in config file\n");
            config_destroy(&cfg);
            exit(EXIT_FAILURE);
        }
        strncpy(conf->resolve_ip, resolve_ip, sizeof(conf->resolve_ip));
    } else {
        fprintf(stderr, "Invalid response_type in config file\n");
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }

    config_destroy(&cfg);
}

void free_config(struct config *conf) {
    for (int i = 0; i < conf->blacklist_items; i++) {
        if(conf->blacklist[i])
          free(conf->blacklist[i]);
    }
    if(conf->blacklist)
      free(conf->blacklist);
}

struct thread_args {
    int sock_fd;
    struct sockaddr_in client_address;
    socklen_t client_addr_len;
    ssize_t bytes_received;
    unsigned char packet[1024];
};

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
  struct DNS_HEADER header;
  unsigned short RC;
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
  if(flags.QR == 0) { //query
      result |= flags.QR;
      result <<= 4;
      result |= flags.op_code;
      result <<= 2; //2 because AA skipped for query type
      result |= flags.TC;
      result <<= 1;
      result |= flags.RD;
      result <<= 2;
      result |= flags.Z;
      result <<= 2;
      result |= flags.NA;
      result <<= 4;
  } else { //means response
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
  }
  return result;
}

struct response {
  unsigned char *response;
  unsigned short size;
};

void change_to_dns_format(char *src, unsigned char *dest) {
  int inputLength = strlen(src);
  int dnsIndex = 0;
  int labelLength = 0;

  for (int i = 0; i <= inputLength; i++) {
      if (src[i] == '.' || src[i] == '\0') {
          dest[dnsIndex++] = labelLength;
          for (int j = i - labelLength; j < i; j++) {
              dest[dnsIndex++] = src[j];
          }
          labelLength = 0;
      } else {
          labelLength++;
      }
  }

  dest[dnsIndex] = '\0';
}

void change_to_dot_format(char *str) {
  int i;
  for (i = 0; i < strlen((const char*)str); ++i) {
    unsigned int len = str[i];
    for (int j = 0; j < len; ++j) {
      str[i] = str[i + 1];
      ++i;
    }
    str[i] = '.';
  }
  str[i - 1] = '\0';
}

struct response generate_response(struct DNS_HEADER_FLAGS flags, struct DNS_RR_FLAGS answer_record) {
  // building a response
  unsigned char *response_packet, *response_packet_start;
  response_packet = malloc(1024);
  memset(response_packet, 0, 1024);
  response_packet_start = response_packet;

  response_packet[0] = answer_record.header.id & 0b11111111;// id
  response_packet[1] = (answer_record.header.id >> 8) & 0b11111111;

  response_packet += 2;

  unsigned short flags_bits = flags_to_header(flags);
  response_packet[0] = (flags_bits >> 8) & 0b11111111;
  response_packet[1] = flags_bits & 0b11111111;
  response_packet += 2;

  response_packet[0] = 0; // questions
  response_packet[1] = answer_record.header.qd_count;
  response_packet += 2;

  response_packet[0] = 0; // answers
  response_packet[1] = answer_record.header.an_count;
  response_packet += 2;

  response_packet[0] = 0; // authority RRs
  response_packet[1] = answer_record.header.ns_count;
  response_packet += 2;

  response_packet[0] = 0; // additional RRs
  response_packet[1] = answer_record.header.ar_count;
  response_packet += 2;

  for (int j = 0; j < answer_record.packet_size; j++) { // copying answer from relay dns response
    response_packet[0] = answer_record.packet[j];
    response_packet++;
  }
  struct response result;
  result.size = response_packet - response_packet_start;
  result.response = malloc(response_packet - response_packet_start);
  memset(result.response, 0, result.size);
  memcpy(result.response, response_packet_start, response_packet - response_packet_start);
  free(response_packet_start);
  return result;
}

struct DNS_RR_FLAGS resolve(const char *query, const char *dns_server) {
  char *input = (char *)malloc((strlen(query) + 1) * sizeof(char));
  if (query) {
    strcpy(input, query);
  } else {
    printf("Error! Query is NULL.\n");
    struct DNS_RR_FLAGS answer_record;
    return answer_record; // empty?
  }

  unsigned char *packet = malloc(1024);
  memset(packet, 0, 1024);
  unsigned char *packet_start = packet;

  // building a header for request
  printf("Building a header...\n");

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);


  packet[0] = (ts.tv_nsec % 65535) & 0b11111111; //id
  packet[1] = ((ts.tv_nsec % 65535) >> 8) & 0b11111111;
  packet += 2;

  struct DNS_HEADER_FLAGS flags;
  flags.QR = 0; //query
  flags.op_code = 0b0000; //standart query (0)
  flags.TC = 0; //not truncated
  flags.RD = 1; //recursion desired
  flags.Z = 0;
  flags.NA = 0;

  unsigned short flags_bits = flags_to_header(flags);
  packet[0] = (flags_bits >> 8) & 0b11111111;
  packet[1] = flags_bits & 0b11111111;
  packet += 2;

  packet[0] = 0; // questions
  packet[1] = 1;
  packet += 2;


  packet[0] = 0; // answers
  packet[1] = 0;
  packet += 2;

  packet[0] = 0; // authority RRs
  packet[1] = 0;
  packet += 2;

  packet[0] = 0; // additional RRs
  packet[1] = 0;
  packet += 2;

  int qname_size = strlen(input) + 2; //size of dns's query format
  unsigned char *qname = malloc(qname_size); //writing qname
  change_to_dns_format(input, qname);
  if(input)
    free(input);

  for(int i = 0; i < qname_size; i++) {
    packet[0] = qname[i];
    packet++;
  }

  free(qname);

  packet[0] = 0; //Type: A
  packet[1] = 1;
  packet += 2;

  packet[0] = 0; //Class: In
  packet[1] = 1;
  packet += 2;


  // creating socket for connecting to DNS
  printf("Creating socket...\n");
  long sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // udp connection
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(53); // 53 UDP port for DNS
  inet_pton(AF_INET, dns_server, &(servaddr.sin_addr));

  // connecting
  printf("Connecting to DNS server...\n");
  connect(sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

  // sending query packet to DNS server
  printf("Sending query packet to DNS server...\n");
  write(sock_fd, packet_start, packet - packet_start);

  // receive response packet from DNS
  printf("Receiving response packet...\n");
  packet = packet_start;
  memset(packet, 0, 1024);
  int received_packet_size = read(sock_fd, packet, 1024);
  if (received_packet_size <= 0) {
    perror("Error while reading sock_fd");
  }
  close(sock_fd);
  printf("Packet size: %d\n", received_packet_size);
  // parsing the header from reply
  printf("Parcing Header from reply...\n");
  struct DNS_HEADER response_header;
  response_header.id = 0;
  response_header.id |= packet[1];
  response_header.id <<= 8;
  response_header.id |= packet[0];
  if (response_header.id == ts.tv_nsec % 65535) {
    printf("Response header ID is same as request header ID: %d.\n",
           response_header.id);
  } else {
    printf("Response ID and request ID is NOT same: %d and %ld!\n",
           response_header.id, ts.tv_nsec % 65535);
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
    char qname[size_of_qname];
    char *qname_ptr = &qname[0];
    for (int j = 12; j < 12 + size_of_qname; j++) {
      *qname_ptr++ = packet_start[j];
    }
    change_to_dot_format(qname);
    printf("QNAME: %s\n", qname);
  }

  // parsing RRs from reply
  printf("Parcing RRs from reply...\n");
  struct DNS_RR_FLAGS answer_record;
  answer_record.header.an_count = response_header.an_count;
  answer_record.header.ns_count = response_header.ns_count;
  answer_record.header.ar_count = response_header.ar_count;
  answer_record.RC = header_flags.RC;
  answer_record.packet_size = 0;
  printf("Received packet size: %d\n", received_packet_size);
  if(received_packet_size < 0) {
    perror("Error with packet size: ");
  }
  for (int i = 12, j = 0; i < received_packet_size; i++) {
    answer_record.packet[j++] = packet[i];
    answer_record.packet_size++;
  }
  free(packet_start);
  return answer_record;
}

void *handle_request(void *args) {
  struct thread_args *thread_args = (struct thread_args *)args;
  int sock_fd = thread_args->sock_fd;
  if (thread_args->bytes_received == -1) {
    printf("Recvfrom failed.\n");
    close(sock_fd);
    free_config(&conf);
    exit(EXIT_FAILURE);
  }

  printf("Received from %s:%d\n", inet_ntoa(thread_args->client_address.sin_addr),
         ntohs(thread_args->client_address.sin_port));

  struct DNS_HEADER request_header;
  request_header.id = 0;
  request_header.id |= thread_args->packet[1];
  request_header.id <<= 8;
  request_header.id |= thread_args->packet[0];

  request_header.flags = 0;
  request_header.flags |= thread_args->packet[2];
  request_header.flags <<= 8;
  request_header.flags |= thread_args->packet[3];

  struct DNS_HEADER_FLAGS flags = parse_header_flags(request_header.flags);

  request_header.qd_count = 0;
  request_header.qd_count |= thread_args->packet[4];
  request_header.qd_count <<= 8;
  request_header.qd_count |= thread_args->packet[5];
  printf("Questions count: %d\n", request_header.qd_count);

  request_header.an_count = 0;
  request_header.an_count |= thread_args->packet[6];
  request_header.an_count <<= 8;
  request_header.an_count |= thread_args->packet[7];
  printf("Answers count: %d\n", request_header.an_count);

  request_header.ns_count = 0;
  request_header.ns_count |= thread_args->packet[8];
  request_header.ns_count <<= 8;
  request_header.ns_count |= thread_args->packet[9];
  printf("Authority RRs count: %d\n", request_header.ns_count);

  request_header.ar_count = 0;
  request_header.ar_count |= thread_args->packet[10];
  request_header.ar_count <<= 8;
  request_header.ar_count |= thread_args->packet[11];
  printf("Additional RRs count: %d\n", request_header.ar_count);

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
        for (int j = 12; thread_args->packet[j] != 0; j++) {
            size_of_cname++;
        }
        char cname[size_of_cname];
        char *cname_ptr = &cname[0];
        for (int j = 12; j < 12 + size_of_cname; j++) {
            *cname_ptr++ = thread_args->packet[j];
        }
        change_to_dot_format(cname);
        printf("CNAME: %s\n", cname);

        for(int i = 0; i < conf.blacklist_items; i++) {
            if(strstr(cname, conf.blacklist[i])) {
                printf("Found blacklisted CNAME: %s\n", cname);
                switch(conf.response_type) {
                case NOT_FOUND: {
                    struct DNS_RR_FLAGS answer_record;
                    answer_record.header.id = request_header.id;
                    answer_record.header.an_count = 0;
                    answer_record.header.qd_count = 1;
                    answer_record.header.ns_count = 0;
                    answer_record.header.ar_count = 0;
                    flags.QR = 1;
                    flags.RA = 1;
                    flags.RC = 3;
                    answer_record.RC = 3;
                    answer_record.packet_size = size_of_cname + 4;
                    answer_record.packet[size_of_cname] = 0x00; //Type A
                    answer_record.packet[size_of_cname+1] = 0x01;
                    answer_record.packet[size_of_cname+2] = 0x00;// Class IN
                    answer_record.packet[size_of_cname+3] = 0x01;
                    change_to_dns_format(cname, answer_record.packet);
                    struct response response = generate_response(flags, answer_record);
                    printf("Sending result\n");
                    printf("size: %d\n", response.size);
                    ssize_t bytes_sent =
                        sendto(thread_args->sock_fd, response.response,
                               response.size, 0,
                               (struct sockaddr *)&thread_args->client_address, thread_args->client_addr_len);
                    if(response.response)
                      free(response.response);
                    if (bytes_sent == -1) {
                        perror("Sendto failed");
                    }
                    if(thread_args)
                      free(thread_args);
                    pthread_exit(NULL);
                    break;
                }
                case REFUSED: {
                    struct DNS_RR_FLAGS answer_record;
                    answer_record.header.id = request_header.id;
                    answer_record.header.an_count = 0;
                    answer_record.header.qd_count = 1;
                    answer_record.header.ns_count = 0;
                    answer_record.header.ar_count = 0;
                    flags.QR = 1;
                    flags.RA = 1;
                    flags.RC = 5;
                    answer_record.RC = 5;
                    answer_record.packet_size = size_of_cname + 4;
                    answer_record.packet[size_of_cname] = 0x00; //Type A
                    answer_record.packet[size_of_cname+1] = 0x01;
                    answer_record.packet[size_of_cname+2] = 0x00;// Class IN
                    answer_record.packet[size_of_cname+3] = 0x01;
                    change_to_dns_format(cname, answer_record.packet);
                    struct response response = generate_response(flags, answer_record);
                    printf("Sending result\n");
                    printf("size: %d\n", response.size);
                    ssize_t bytes_sent =
                        sendto(thread_args->sock_fd, response.response,
                               response.size, 0,
                               (struct sockaddr *)&thread_args->client_address, thread_args->client_addr_len);

                    if(response.response)
                      free(response.response);
                    if (bytes_sent == -1) {
                        perror("Sendto failed");
                    }
                    if(thread_args)
                      free(thread_args);
                    pthread_exit(NULL);
                    break;
                }
                case RESOLVE: {
                    struct DNS_RR_FLAGS answer_record;
                    answer_record.header.id = request_header.id;
                    answer_record.header.an_count = 1; //one answer
                    answer_record.header.qd_count = 1;
                    answer_record.header.ns_count = 0;
                    answer_record.header.ar_count = 0;
                    flags.QR = 1;
                    flags.RA = 1;
                    flags.RC = 0;
                    answer_record.RC = 0;
                    change_to_dns_format(cname, answer_record.packet);
                    answer_record.packet_size = size_of_cname + 20;
                    answer_record.packet[size_of_cname] = 0x00; //Type A
                    answer_record.packet[size_of_cname+1] = 0x01;
                    answer_record.packet[size_of_cname+2] = 0x00;// Class IN
                    answer_record.packet[size_of_cname+3] = 0x01;

                    //adding response
                    answer_record.packet[size_of_cname+4] = 0xc0;
                    answer_record.packet[size_of_cname+5] = 0x0c;

                    answer_record.packet[size_of_cname+6] = 0x00;
                    answer_record.packet[size_of_cname+7] = 0x01; //Type A

                    answer_record.packet[size_of_cname+8] = 0x00;
                    answer_record.packet[size_of_cname+9] = 0x01; //Class IN

                    answer_record.packet[size_of_cname+10] = 0x00; //TTL
                    answer_record.packet[size_of_cname+11] = 0x00;
                    answer_record.packet[size_of_cname+12] = 0x01; //5 minutes (300 secs)
                    answer_record.packet[size_of_cname+13] = 0x2c;

                    answer_record.packet[size_of_cname+14] = 0x00;
                    answer_record.packet[size_of_cname+15] = 0x04; //Data length: 4

                    sscanf(conf.resolve_ip, "%d.%d.%d.%d",
                           &answer_record.packet[size_of_cname+16],
                           &answer_record.packet[size_of_cname+17],
                           &answer_record.packet[size_of_cname+18],
                           &answer_record.packet[size_of_cname+19]);

                    struct response response = generate_response(flags, answer_record);
                    printf("Sending result\n");
                    printf("size: %d\n", response.size);
                    ssize_t bytes_sent =
                        sendto(thread_args->sock_fd, response.response,
                               response.size, 0,
                               (struct sockaddr *)&thread_args->client_address, thread_args->client_addr_len);
                    if(response.response)
                      free(response.response);
                    if (bytes_sent == -1) {
                        perror("Sendto failed");
                    }
                    if(thread_args)
                      free(thread_args);
                    pthread_exit(NULL);
                    break;
                }

                }
            }
        }

        // got CNAME, sending to RELAY
        struct DNS_RR_FLAGS answer_record = resolve(cname, conf.upstream_ip);
        answer_record.header.qd_count = request_header.qd_count;
        answer_record.header.id = request_header.id;
        // printf("IP: %s\n", answer_record.ip);

        // if(answer_record.ip)
        //   free(answer_record.ip);
        flags.QR = 1; // response
        flags.RA = 1; // recursion is available
        flags.RC = answer_record.RC;
        struct response response = generate_response(flags, answer_record);

        printf("Sending result\n");
        printf("size: %d\n", response.size);
        ssize_t bytes_sent =
            sendto(thread_args->sock_fd, response.response,
                   response.size, 0,
                   (struct sockaddr *)&thread_args->client_address, thread_args->client_addr_len);
        if(response.response)
          free(response.response);
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

  if(thread_args)
    free(thread_args);
  pthread_exit(NULL);
}

void server() {
  // creating socket for hosting DNS
  printf("Creating socket for hosting...\n");
  long sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // udp connection
  if (sock_fd == -1) {
    printf("Socket creation failed.\n");
    free_config(&conf);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  server_address.sin_port = htons(53);

  if (bind(sock_fd, (struct sockaddr *)&server_address,
           sizeof(server_address)) == -1) {
    perror("Bind failed");
    close(sock_fd);
    free_config(&conf);
    exit(EXIT_FAILURE);
  }

  printf("Listening on port 53...\n");

  while (1) {
    struct sockaddr_in client_address;
    socklen_t client_addr_len = sizeof(client_address);
    struct thread_args *thread_args = malloc(sizeof(struct thread_args));

    ssize_t bytes_received = recvfrom(sock_fd, &thread_args->packet, 1024, 0, (struct sockaddr *)&client_address, &client_addr_len);
    if (bytes_received == -1) {
      perror("recvfrom failed");
      continue;
    }


    if (thread_args == NULL) {
      perror("Memory allocation failed");
      continue;
    }
    thread_args->sock_fd = sock_fd;
    thread_args->bytes_received = bytes_received;
    thread_args->client_address = client_address;
    thread_args->client_addr_len = client_addr_len;

    pthread_t tid;
    int ret = pthread_create(&tid, NULL, handle_request, (void *)thread_args);
    if (ret != 0) {
      perror("Thread creation failed");
      if(thread_args)
        free(thread_args);
      continue;
    }

    pthread_detach(tid);
  }
}

int main(int argc, char *argv[]) {

  if (argc == 1) {
    //no command-line arguments specified, try loading config from the current folder
    if (access("config.conf", F_OK) == 0) {
      load_config("config.conf", &conf);
    } else {
      //configuration file not found in the current folder
      printf("Can't load config.conf from current folder.\nDNS-Proxy: Usage: -c <config_file_path>\n");
      return 1;
    }
  } else if (argc == 3 && strcmp(argv[1], "-c") == 0) {
    //command-line argument specified, check if it's "-c" followed by a file path
    load_config(argv[2], &conf);
  } else {
    //invalid command-line arguments
    printf("DNS-Proxy: Usage: -c <config_file_path>\n");
    return 1;
  }

  printf("upstream_ip: %s\n", conf.upstream_ip);
  printf("blacklist:\n");
  for (int i = 0; i < conf.blacklist_items; i++) {
    printf("  %s\n", conf.blacklist[i]);
  }
  printf("response_type: %d\n", conf.response_type);
  printf("resolve_ip: %s\n", conf.resolve_ip);

  //resolve("polisan.ddns.net", "8.8.8.8");
  server();

  free_config(&conf);
  return 0;
}
