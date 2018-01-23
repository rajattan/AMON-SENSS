#ifndef __UTILS_H
#define __UTILS_H

#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <map>


using namespace std;

#define HMB 1.1
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
#define BACKLOG 30
#define ATTACK_LOW 30    /* Make this a configurable param */
#define ATTACK_HIGH 60  /* Make this a configurable param */
#define HIST_LEN 3600    /* How long we remember history */
#define MIN_TRAIN 3600
#define NUMSTD 5
#define MAX_SAMPLES 100
#define MIN_SAMPLES 2
#define MAX_FLOW_SIZE 10000;
#define FILTER_THRESH 0.0
#define SIG_FLOWS 100
#define SPEC_THRESH 0.05
#define MAX_DIFF 10
#define BIG_MSG MAX_SAMPLES*MAX_LINE


struct flow_t{
  unsigned int src;
  unsigned short sport;
  unsigned int dst;
  unsigned short dport;
  unsigned char proto;

  bool operator<(const flow_t& rhs) const
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
    else if (src == rhs.src && sport == rhs.sport && dst == rhs.dst && dport == rhs.dport && proto < rhs.proto)
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



struct stat_f
{
  long timestamp;
  int vol;
  int oci;
  flow_t sig;
  map <flow_t,int> matchedflows;
  map <flow_t,int> reverseflows;
};

struct sample_p
{
  vector<flow_p> flows;
  map<flow_t,stat_r> signatures;
};

struct sample
{
  sample_p bins[BRICK_DIMENSION];
};

  
int sha_hash(u_int32_t ip);

int sgn(double x);

int bettersig(flow_t a, flow_t b);

string printsignature(flow_t s);
#endif
