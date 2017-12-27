#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>

#ifndef __UTILS_H
#define __UTILS_H

#define FILE_INTERVAL 3600
#define TIMEZONE_ADJUST 5*3600
#define BRICK_DIMENSION 128*128 
#define MAX_NUM_DEVS 64
#define MAXLEN 128
#define CONFIG_FILE "amon.config"
#define VERBOSE_SUPPORT
#define MAX_LINE 255
#define TCP 6
#define UDP 17
#define BUF_SIZE 100
#define AR_LEN 30

struct flow_t{ 
 u_int32_t src;
 u_int32_t dst;
 u_int16_t sport;
 u_int16_t dport;
 };

struct flow_p
{
  long time;
  int len;
  int oci;
  flow_t flow;
};

int sha_hash(u_int32_t ip);

#endif
