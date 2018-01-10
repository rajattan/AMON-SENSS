#ifndef __UTILS_H
#define __UTILS_H

#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <map>


using namespace std;

#define FILE_INTERVAL 3600 
#define TIMEZONE_ADJUST 5*3600
#define BRICK_DIMENSION 256
#define MAX_NUM_DEVS 64
#define MAXLEN 128
#define CONFIG_FILE "amon.config"
#define VERBOSE_SUPPORT
#define MAX_LINE 255
#define TCP 6
#define UDP 17
#define BUF_SIZE 1000
#define AR_LEN 30
#define AMON_PORT 10000
#define BACKLOG 30
#define ATTACK_LOW 20    /* Make this a configurable param */
#define ATTACK_HIGH 120  /* Make this a configurable param */
#define HIST_LEN 3600    /* How long we remember history */
#define MIN_TRAIN 3600
#define NUMSTD 5
#define MAX_SAMPLES 100
#define MIN_SAMPLES 2
#define MAX_FLOW_SIZE 10000;
#define FILTER_THRESH 0.3
#define MAX_DIFF 10
#define BIG_MSG MAX_SAMPLES*MAX_LINE

enum stype{src, dst, sport, dport, dstdport, srcsport, srcdst, dstsport};

struct sig_b{
  unsigned int src;
  unsigned short sport;
  unsigned int dst;
  unsigned short dport;

  bool operator<(const sig_b& rhs) const
  {
    if (src < rhs.src)
      {
	return true;
      }
    else if (src == rhs.src && sport < rhs.sport)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst < rhs.dst)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst == rhs.dst && dport < rhs.dport)
      {
	return true;
      }
    else
      return false;
  }
};

struct indic{
  int bin;
  int oci;
  long timestamp;
};

struct flow_t{ 
 u_int32_t src;
 u_int32_t dst;
 u_int16_t sport;
 u_int16_t dport;
 };

struct flow_p
{
  long start;
  long end;
  int len;
  int oci;
  flow_t flow;
};

struct stat_r
{
  int vol;
  int oci;
  double volp;
  double ocip;
};

struct sample
{
  vector<flow_p> flows;
  map<sig_b,stat_r> signatures;
  char raw[MAX_SAMPLES][MAX_LINE];
};
  
int sha_hash(u_int32_t ip);

int sgn(double x);

int bettersig(sig_b a, sig_b b);
#endif
