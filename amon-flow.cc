//================================================================================//
//================================================================================//
/*
 *
 * (C) 2015 - Michalis Kallitsis <mgkallit@merit.edu>
 *            Stilian Stoev <sstoev@umich.edu>
 *            George Michailidis <gmichail@ufl.edu>
 *            Modified by Jelena Mirkovic <sunshine@isi.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * published by the Free Software Foundation; either version 3 of the License, 
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * 
 */
//================================================================================//
//================================================================================//

#include <signal.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sched.h>
//#include <stdlib.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <monetary.h>
#include <locale.h>
#include <pcap.h>
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <cmath>

#include <streambuf>
#include <dirent.h>

#include "pfring.h"
#include "pfutils.c"
#include "utils.h"

int* delimiters;
int interval=3;
int reporters=0;
int reported=0;
map<int, int> adms;
fd_set readset, writeset;

int isready;
long dbTime = 0;
long curTime = 0;

int training_done = 0;

using namespace std;

class DataBuf : public streambuf
{
public:
  DataBuf(char * d, size_t s) {
    setg(d, d, d + s);
  }
};

void parse(char* input, char delimiter, int** array)
{
  int pos = 0;
  memset(*array, 255, AR_LEN);
  int len = strlen(input);
  for(int i = 0; i<len; i++)
    {
      if (input[i] == delimiter)
	{
	  (*array)[pos] = i+1;
	  input[i] = 0;
	  pos++;
	}
    }
}

long buf_time = 0;
int buf_cnt = 0;
int buf_i = 0;
pfring *pd[MAX_NUM_DEVS];
struct pollfd pfd[MAX_NUM_DEVS];
int num_devs = 0;
#ifdef VERBOSE_SUPPORT
int verbose = 0;
#endif
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 0, do_shutdown = 0;
int poll_duration = DEFAULT_POLL_DURATION;

//=======================================//
//==== Declare AMON-related variables====//
//=======================================//

struct cell
{
  unsigned int databrick_p[BRICK_DIMENSION];	 /* databrick payload */
  int databrick_s[BRICK_DIMENSION];	         /* databrick symmetry */
  //unsigned int wfilter_p[BRICK_DIMENSION];	 /* payload w filter */
  //int wfilter_s[BRICK_DIMENSION];	         /* symmetry w filter */
  int fresh;
};


ofstream debug[BRICK_DIMENSION];
int is_attack[BRICK_DIMENSION];
int is_abnormal[BRICK_DIMENSION]; 
ofstream outfiles[BRICK_DIMENSION];


char filename[MAXLEN];
map<long,cell> cells;
map<long,map<int, sample>> samples;
map<int,stat_f> signatures;
long firsttime = 0;    /* Beginning of trace */
long updatetime = 0;   /* Time of last update */
long statstime = 0;    /* Time when we move the stats to history */
int traceid = 0;
char im[BIG_MSG];
int imlen = 0;
int admsg = 0;
int seqnum = 0;

pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t samples_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t indicator_lock = PTHREAD_MUTEX_INITIALIZER;

/* Make sure we don't fire if data is not ready */
pthread_mutex_t time_sync_lock = PTHREAD_MUTEX_INITIALIZER;


struct passingThreadParams
{
  int caller_id;
  int callee_id;
};


struct conf_param
{
  int alarm_sleep;
  int default_snaplen;
  char default_device[MAXLEN];
  char user[MAXLEN];
  char pass[MAXLEN];
  char db_client[MAXLEN];
  char database[MAXLEN];
  char db_collection[MAXLEN];
  int seed;
  char strata_file[MAXLEN];
  char prefix_file[MAXLEN];
}
conf_param;
struct conf_param parms;



//====================================================//
//===== Function to trim strings for config file =====//
//====================================================//
char *trim(char *str)
{
    size_t len = 0;
    char *frontp = str;
    char *endp = NULL;

    if( str == NULL ) { return NULL; }
    if( str[0] == '\0' ) { return str; }

    len = strlen(str);
    endp = str + len;

    while( isspace((unsigned char) *frontp) ) { ++frontp; }
    if( endp != frontp )
    {
        while( isspace((unsigned char) *(--endp)) && endp != frontp ) {}
    }

    if( str + len - 1 != endp )
            *(endp + 1) = '\0';
    else if( frontp != str &&  endp == frontp )
            *str = '\0';

    endp = str;
    if( frontp != str )
    {
            while( *frontp ) { *endp++ = *frontp++; }
            *endp = '\0';
    }

    return str;
}

//=====================================================//
//===== Function to parse strings for config file =====//
//=====================================================//
void
parse_config (struct conf_param * parms)
{
  char *s, buff[256];
  FILE *fp = fopen (CONFIG_FILE, "r");
  if (fp == NULL)
  {
    printf ("\n Config file %s does not exist. Please include it and re-run.. \n",CONFIG_FILE);
    exit (0);
  }
  printf ("\n Reading config file %s ...",CONFIG_FILE);
  while ((s = fgets (buff, sizeof buff, fp)) != NULL)
  {
        /* Skip blank lines and comment lines */
        if (buff[0] == '\n' || buff[0] == '#')
          continue;

        /* Parse name/value pair from line */
        char name[MAXLEN], value[MAXLEN];
        memset(name, '\0', sizeof(name));
        memset(value, '\0', sizeof(value));
        s = strtok (buff, "=");
        if (s==NULL)
          continue;
        else
        {  strcpy (name, s);
           trim (name);
        } 
        s = strtok (NULL, "=");
        if (s==NULL)
          continue;
        else
        {
          strcpy (value, s);
          trim (value);
        }

        /* Copy into correct entry in parameters struct */
        if ( strcasecmp(name, "alarm_sleep")==0)
        {
          parms->alarm_sleep = atoi( value);
        }
        else if ( strcasecmp(name, "default_snaplen")==0)
        {
          parms->default_snaplen = atoi( value);
        }
        else if ( strcasecmp(name, "default_device")==0)
        {
          strncpy (parms->default_device, value, MAXLEN);
        }
        else if ( strcasecmp(name, "mongo_db_client")==0 ||  strcasecmp(name, "db_client")==0)
        {
          strncpy (parms->db_client, value, MAXLEN);
        }
	else if ( strcasecmp(name, "user")==0)
        {
          strncpy (parms->user, value, MAXLEN);
        }
	else if ( strcasecmp(name, "pass")==0)
        {
          strncpy (parms->pass, value, MAXLEN);
        }
        else if ( strcasecmp(name, "database")==0)
        {
          strncpy (parms->database, value, MAXLEN);
        }
        else if ( strcasecmp(name, "db_collection")==0)
        {
          strncpy (parms->db_collection, value, MAXLEN);
        }
        else if ( strcasecmp(name, "seed")==0)
        {
          parms->seed = atoi( value);
        }
        else if( strcasecmp(name, "strata_file")==0)
        {
          strncpy (parms->strata_file, value, MAXLEN);
        }
        else if( strcasecmp(name, "prefix_file")==0)
        {
          strncpy (parms->prefix_file, value, MAXLEN);
        }
        else
        {  printf ("WARNING: %s/%s: Unknown name/value pair!\n",
           name, value);
        }
  }

  fclose (fp);
}


long calcSignature(long timestamp, int index, int aoci)
{
  int diff = MAX_DIFF;
  long timeinmap = 0;
  long t = timestamp;
  if (samples.find(timestamp) == samples.end())
    {
      for (map<long,map<int,sample>>::iterator it = samples.begin(); it != samples.end(); it++)
	{
	  if (abs(it->first - timestamp) < diff)
	    {
	      timeinmap = it->first;
	      diff = abs(it->first - timestamp);
	    }
	}
      if (timeinmap == 0)
	return 0;
      else
	t = timeinmap;
    }
  if (samples[t][index].flows.size() >= MIN_SAMPLES)
    {
      /* Find a signature if it exists */
      map <sig_b,stat_r> sigs[16];
      int vol = 0;
      int oci = 0;
      int i = 0;
      for (vector<flow_p>::iterator fit = samples[t][index].flows.begin(); fit != samples[t][index].flows.end(); fit++)
	{
	  flow_p f = *fit;
	  i++;
	  // If different sign drop this flow sample
	  if (sgn(f.oci) != sgn(aoci))
	    continue;

	  vol += f.len;
	  oci += f.oci;
	  for (int s=0; s<16; s++)
	    {
	      // Default signature matches everything
	      // zero is a special value, matching everything.
	      // Only allow signatures where destination is known.
	      sig_b key = {0,0,0,0,0};
	      key.dst = f.flow.dst;
	      // src, sport, dport, proto
	      if ((s & 8) > 0)
		key.src = f.flow.src;
	      if ((s & 4) > 0)
		key.sport = f.flow.sport;
	      if ((s & 2) > 0)
		key.dport = f.flow.dport;
	      if ((s & 1) > 0)
		key.proto = f.flow.proto;
	      if (sigs[s].find(key) == sigs[s].end())
		sigs[s][key] = {0,0};
	      sigs[s][key].vol += f.len;
	      sigs[s][key].oci += f.oci;
	    }
	}
      for (int s=0; s<16; s++)
	{
	  // Find the best signatures
	  for (map<sig_b,stat_r>::iterator sit=sigs[s].begin(); sit != sigs[s].end(); sit++)
	    {
	      sig_b k = sit->first;
	      if (abs(sit->second.oci) > abs(oci) * FILTER_THRESH)
		{
		  samples[t][index].signatures[sit->first] = {sit->second.vol, sit->second.oci, (double)sit->second.vol/vol, (double)sit->second.oci/oci};	     
		}
	    }
	}
    }
  return t;
}


/*****************************************************************/

void addSample(int index, flow_p f, long i)
{
  /* Decide based on flow size and asymmetry if to add it or not */
  int toadd = rand() % MAX_FLOW_SIZE;
  
  /* Add asymmetric flows, and add longer flows before shorter ones */
  if (f.oci == 0)
    return;

  if (samples.find(i) == samples.end())
    {
      map<int,sample> m;
      samples.insert(pair<long,map<int,sample>>(i,m));
    }
  if (samples[i].find(index) == samples[i].end())
    {
      sample s;
      samples[i].insert(pair<int,sample>(index,s));
    }
  int s = samples[i][index].flows.size();
  if (samples[i][index].flows.size() < MAX_SAMPLES)
    {
      samples[i][index].flows.push_back(f);
      //memcpy(samples[i][index].raw[s],line,strlen(line));
    }
  else
    {
      if (toadd > f.len)
	return;
      
      /* Replace the flow you have already if this one is 
	 bigger or more asymmetric */
      int j = rand() % MAX_SAMPLES;
      if ((abs(samples[i][index].flows[j].oci) < abs(f.oci)) ||
	  (samples[i][index].flows[j].len < f.len))
	{
	  samples[i][index].flows[j] = f;
	}
    }
}

int match(flow_t flow, sig_b sig)
{
  if (flow.proto != sig.proto && sig.proto != 0)
    return 0;
  if ((flow.src == sig.src || sig.src == 0) &&
      (flow.sport == sig.sport || sig.sport == 0) &&
      (flow.dst == sig.dst || sig.dst == 0) &&
      (flow.dport == sig.dport || sig.dport == 0))
    return 1;
  else
    return 0;
}

/*****************************************************************/

void
amonProcessing(flow_t flow, int len, long start, long end, int oci, char* line)
{
  int d_bucket = 0, s_bucket = 0;	    /* indices for the databrick */
  int error;
  unsigned int payload;

  if (buf_time == 0)
    {
      buf_time = end;
      buf_cnt = 1;
    }
  else if (buf_time != end)
    {
      buf_cnt--;
      if (buf_cnt == 0)
	{
	  buf_time = end;
	  buf_cnt = 1;
	}
    }
  else
    buf_cnt++;

  dbTime = buf_time;
  
  s_bucket = sha_hash(flow.src); /* Jelena: should add  & mask */
  d_bucket = sha_hash(flow.dst); /* Jelena: should add  & mask */
  
  cell c;
  memset(c.databrick_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c.databrick_s, 0, BRICK_DIMENSION*sizeof(int));
  //memset(c.wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  //memset(c.wfilter_s, 0, BRICK_DIMENSION*sizeof(int));
  // Standardize time
  start = int(start / interval)*interval;
  end = int(end / interval)*interval;
  for (long i = start; i <= end; i+= interval)
    {
        int error;
	if ((error = pthread_mutex_lock (&cells_lock)))
	  {
	    fprintf (stderr,
		     "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		     error);
	    exit (-1);
	  }

      if (cells.find(i) == cells.end())
	{
	  cells.insert(pair<long,cell>(i,c));
	}
      cells[i].databrick_p[d_bucket] += len;	// add bytes to payload databrick for dst
      cells[i].databrick_s[d_bucket] += oci;	// add oci to symmetry databrick for dst
      cells[i].databrick_s[s_bucket] -= oci;	// subtract oci from symmetry databrick for src
      //cells[i].wfilter_p[d_bucket] += len;	// add bytes to payload databrick for dst
      //cells[i].wfilter_s[d_bucket] += oci;	// add oci to symmetry databrick for dst
      ///cells[i].wfilter_s[s_bucket] -= oci;	// subtract oci from symmetry databrick for src
      cells[i].fresh = 1;
      
      if (is_attack[d_bucket])
	{
	  if (match(flow, signatures[d_bucket].sig))
	    {
	      /* Project how much traffic would be dropped */
	      if (oci == 0)
		signatures[d_bucket].goodflows += 1;
	      else
		signatures[d_bucket].badflows += oci;
	      /* Undo changes for wfilter */
	      //cells[i].wfilter_p[d_bucket] -= len;	
	      //cells[i].wfilter_s[d_bucket] -= oci;	
	      //cells[i].wfilter_s[s_bucket] += oci;	
	    }
	}
      if ((error = pthread_mutex_unlock (&cells_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      /*
	if ((error = pthread_mutex_lock (&samples_lock)))
	  {
	    fprintf (stderr,
		     "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		     error);
	    exit (-1);
	  }
      */

	flow_p f={start, end, len, oci, flow};
	addSample(d_bucket, f, i);
	/*
	if ((error = pthread_mutex_unlock (&samples_lock)))
	  {
	    fprintf (stderr,
		     "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		     error);
	    exit (-1);
	  }
      */
    }
}


void
amonProcessingNfdump (char* line, long time)
{
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  // Get start and end time of a flow
  char* tokene;
  char saveline[MAX_LINE];
  memcpy(saveline, line, strlen(line));
  parse(line,'|', &delimiters);
  long start = strtol(line+delimiters[0], &tokene, 10);
  long end = strtol(line+delimiters[2], &tokene, 10);
  int dur = end - start;
  // Normalize duration
  if (dur < 0)
    dur = 0;
  if (dur > 3600)
    dur = 3600;
  int pkts, bytes;

  /* Get source and destination IP and port and protocol */
  flow_t flow = {0,0,0,0};
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  int proto = atoi(line+delimiters[4]);
  flow.src = strtol(line+delimiters[8], &tokene, 10);
  flow.sport = atoi(line+delimiters[9]); // sport
  flow.dst = strtol(line+delimiters[13], &tokene, 10);
  flow.dport = atoi(line+delimiters[14]); // dport
  flow.proto = proto;
  int flags = atoi(line+delimiters[19]);
  pkts = atoi(line+delimiters[21]);
  pkts = (int)(pkts/(dur+1))+1;
  bytes = atoi(line+delimiters[22]);
  bytes = (int)(bytes/(dur+1))+1;

  /* Is this outstanding connection? For TCP, connections without 
     PUSH are outstanding. For UDP, connections that have a request
     but not a reply are outstanding. Because bidirectional flows
     may be broken into two unidirectional flows we have values of
     0, -1 and +1 for outstanding connection indicator or oci. For 
     TCP we use 0 (there is a PUSH) or 1 (no PUSH) and for UDP/ICMP we 
     use +1 for requests and -1 for replies. */
  int oci;
  if (proto == TCP)
    {
      // There is a PUSH flag
      if ((flags & 8) > 0)
	oci = 0;
      else
	oci = 1;
    }
  else if (proto == UDP)
    {
      // Quick and dirty check if this is request
      // or reply
      // reply, switch src and dst so it can go to the
      // right databrick
      if (flow.sport < 1024 && flow.dport >= 1024)
	oci = -1*pkts;
      // request
      else if (flow.sport >= 1024 && flow.dport < 1024)
	oci = 1*pkts;
      // unknown, do nothing
      else
	oci = 0;
    }
  else
    // unknown, do nothing
    oci=0;
  amonProcessing(flow, bytes, start, end, oci, saveline);
}

void
amonProcessingPcap (struct pfring_pkthdr *h, const u_char * p, long time)
{
  struct ether_header ehdr;
  u_short eth_type;
  struct ip ip;
  flow_t flow = {0,0,0,0};
  u_int32_t displ = 0;
  u_int32_t src_omega;		            /* The SRC IP in its integer representation */
  u_int32_t dst_omega;		            /* The DST IP in its integer representation */
  int len = 0;

  memcpy (&ehdr, p, sizeof (struct ether_header));
  eth_type = ntohs (ehdr.ether_type);

  if (eth_type == 0x8100)
    {
      eth_type = (p[16]) * 256 + p[17];
      displ += 4;
      p += 4;
    }

  if (eth_type == 0x0800)
    {
      memcpy (&ip, p + sizeof (ehdr),sizeof (struct ip));        
      src_omega = ntohl (ip.ip_src.s_addr);
      dst_omega = ntohl (ip.ip_dst.s_addr);
      /* Find out ports */
      
      pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 0, 0);
      if(h->extended_hdr.parsed_pkt.l4_src_port == 0 && h->extended_hdr.parsed_pkt.l4_dst_port == 0)
      {
        memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
        pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 0, 0);
      }

      flow.src = src_omega;
      flow.dst = dst_omega;
      flow.sport = h->extended_hdr.parsed_pkt.l4_src_port;
      flow.dport = h->extended_hdr.parsed_pkt.l4_dst_port;
      len = h->len;
      /* TODO handle OCI here */     
      amonProcessing(flow, len, time, time, 0, 0);
    }
}




/* Types of statistics. If this changes, update the entire section */
enum period{cur, hist};
enum type{n, avg, ss};
enum dim{vol, sym};
double stats[2][3][2][BRICK_DIMENSION]; /* statistics for attack detection, 
first dim - CUR, HIST, second dim - N, AVG, SS, third dim - VOL, SYM */

struct record
{
  unsigned int timestamp;
  double avgv;
  double avgs;
  double stdv;
  double stds;
  double valv;
  double vals;
};
/* Circular array of records so that when we detect attacks we 
   can generate useful info */
record records[HIST_LEN][BRICK_DIMENSION];
int ri=0;


//=================================================================//
//===== Function to detect values higher than mean + NUMSTD * stdev ====//
//=================================================================//
int abnormal(int type, int index, unsigned int timestamp)
{
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/(stats[hist][n][type][index]-1));
  int data;
  if (type == vol)
    data = cells[timestamp].databrick_p[index];
  else
    data = cells[timestamp].databrick_s[index];

  if (type == vol && data > mean + NUMSTD*std)
    return 1;
  else if (type == sym && abs(data) > abs(mean) + NUMSTD*abs(std))
    return 1;
  else
    return 0;
}

void detect_attack(long timestamp)
{
  if (timestamp <= updatetime)
    return;
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      double avgv = stats[hist][avg][vol][i];
      double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
      double avgs = stats[hist][avg][sym][i];
      double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));

      records[ri][i].timestamp = timestamp;
      records[ri][i].avgv = avgv;     
      records[ri][i].avgs = avgs;
      records[ri][i].stdv = stdv;
      records[ri][i].stds = stds;
      records[ri][i].valv = cells[timestamp].databrick_p[i];
      records[ri][i].vals = cells[timestamp].databrick_s[i];

      debug[i]<<records[ri][i].timestamp<<" "<<records[ri][i].avgv<<" ";
      debug[i]<<records[ri][i].stdv<<" "<<records[ri][i].valv<<" ";
      debug[i]<<records[ri][i].avgs<<" "<<records[ri][i].stds<<" ";
      debug[i]<<records[ri][i].vals<<" ";
      //debug[i]<<cells[timestamp].wfilter_p[i]<<"  ";
      //debug[i]<<cells[timestamp].wfilter_s[i]<<"  ";
      debug[i]<<is_attack[i]<<endl;
      
      if (is_attack[i])
	{
	  outfiles[i] <<records[ri][i].timestamp<<" "<<records[ri][i].avgv<<" ";
	  outfiles[i] <<records[ri][i].stdv<<" "<<records[ri][i].valv<<" ";
	  outfiles[i] <<records[ri][i].avgs<<" "<<records[ri][i].stds<<" ";
	  outfiles[i] <<records[ri][i].vals<<" 1"<<endl;
	}
      if (training_done && abnormal(vol, i, timestamp) && abnormal(sym, i, timestamp))
	{
	  if (is_abnormal[i] < int(ATTACK_HIGH/interval))
	    {
	      is_abnormal[i]++;
	      cout<<timestamp<<" abnormal for "<<i<<" points "<<is_abnormal[i]<<endl;
	    }
	  int v=cells[timestamp].databrick_p[i];
	  int s=cells[timestamp].databrick_s[i];
	  if (is_abnormal[i] >= int(ATTACK_LOW/interval)
	      && is_attack[i] == 0)
	    {
	      /* Signal attack detection */
	      is_attack[i] = 1;

	      // Find closest timestamp and calculate signatures
	      long t = calcSignature(timestamp, i, s);

	      // Open signature file
	      ofstream sout;
	      sprintf(filename,"%d.%u.sig", i, t);
	      sout.open(filename);

	      // Find best signature
	      sig_b bestsig = {0,0,0,0,0};
	      int vol = 0;
	      int oci = 0;
	      double volp = 0;
	      double ocip = 0;
	      
	      for (map<sig_b,stat_r>::iterator sit = samples[t][i].signatures.begin(); sit != samples[t][i].signatures.end(); sit++)
		{
		  // Print out each signature for debugging
		  sout<<"Best "<<i<<" "<<printsignature(sit->first)<<" v="<<sit->second.vol<<"("<<sit->second.volp<<") o="<<sit->second.oci<<" ("<<sit->second.ocip<<")"<<endl;
		  if (abs(samples[t][i].signatures[sit->first].oci) > abs(oci) ||
		      (samples[t][i].signatures[sit->first].oci == oci && bettersig(sit->first, bestsig)))
		    {
		      bestsig = sit->first;
		      vol = sit->second.vol;
		      oci = sit->second.oci;
		      volp = sit->second.volp;
		      ocip = sit->second.ocip;
		    }
		}
	      // Remember the signature
	      stat_f sf = {bestsig,0,0};
	      signatures.insert(pair<int, stat_f>(i,sf));
	      sout<<"Best "<<i<<" "<<printsignature(bestsig)<<" v="<<vol<<"("<<volp<<") o="<<oci<<" ("<<ocip<<")"<<endl;
	      sout.close();
	      cout <<" Attack detected in destination bin " << i << " time " << timestamp <<" mean "<<avgv<<" + 5*"<< stdv<<" < "<<cells[timestamp].databrick_p[i]<<" and "<<avgs<<" +- 5*"<<stds<<" inside "<<cells[timestamp].databrick_s[i]<<" flag "<<is_attack[i]<<endl;
	      cout<<"Best "<<i<<" "<<printsignature(bestsig)<<" v="<<vol<<"("<<volp<<") o="<<oci<<" ("<<ocip<<")"<<endl;

	      /* Dump records into a file */
	      ofstream out;
	      out.open("alerts.txt", std::ios_base::app);
	      float volume = float(cells[timestamp].databrick_p[i])*8/1024/1024/1024;
	      out << "START "<<i<<" "<<timestamp<<" vol "<<volume<<" Gbps"<<endl;
	      out.close();
	      sprintf(filename,"%d.log.%u", i, timestamp);
	      outfiles[i].close();
	      outfiles[i].open(filename);
	      for (int j = (ri+1)%HIST_LEN; j != ri; )
		{
		  if (records[j][i].timestamp > 0)
		    {
			  outfiles[i] <<records[j][i].timestamp<<" "<<records[j][i].avgv<<" ";
			  outfiles[i] <<records[j][i].stdv<<" "<<records[j][i].valv<<" ";
			  outfiles[i] <<records[j][i].avgs<<" "<<records[j][i].stds<<" ";
			  outfiles[i] <<records[j][i].vals<<" 0"<<endl;
		    }
		  j++;
		  if (j == HIST_LEN)
		    j = 0;
		}
	      outfiles[i] <<records[ri][i].timestamp<<" "<<records[ri][i].avgv<<" ";
	      outfiles[i] <<records[ri][i].stdv<<" "<<records[ri][i].valv<<" ";
	      outfiles[i] <<records[ri][i].avgs<<" "<<records[ri][i].stds<<" ";
	      outfiles[i] <<records[ri][i].vals<<" 1"<<endl;
	    }
	}
      else if (training_done && !abnormal(vol, i, timestamp) && !abnormal(sym, i, timestamp))
	{
	  if (is_abnormal[i] > 0)
	    {
	      is_abnormal[i] --;
	      cout<<timestamp<<" NOT abnormal for "<<i<<" points "<<is_abnormal[i]<<endl;
	    }
	  if (is_attack[i] > 0 && is_abnormal[i] == 0)
	    {
	      /* Signal end of attack */
	      cout <<" Attack has stopped in destination bin "<< i << " time " << timestamp <<" good dropped "<<signatures[i].goodflows<<" bad dropped "<<signatures[i].badflows<<endl;
	      ofstream out;
	      out.open("alerts.txt", std::ios_base::app);
	      out << "STOP "<<i<<" "<<timestamp<<" "<<signatures[i].goodflows<<" "<<signatures[i].badflows<<endl;
	      out.close();
	      signatures.erase(i);
	      is_attack[i] = 0;
	    }
	}
    }
  ri++;
  if (ri == HIST_LEN)
    ri = 0;
}

void update_dst_arrays(long timestamp)
{
  if (timestamp <= updatetime)
      return;
  if (training_done)
    {
      for (int i=0;i<BRICK_DIMENSION;i++)
	{
	  for (int j=vol; j<=sym; j++)
	    {
	      int data;
	      if (j == vol)
		data = cells[timestamp].databrick_p[i];
	      else
		data = cells[timestamp].databrick_s[i];
	      /* Only update if everything looks normal */
	      if (!is_abnormal[i])
		{
		  // Update avg and ss
		  stats[cur][n][j][i] += 1;
		  if (stats[cur][n][j][i] == 1)
		    {
		      stats[cur][avg][j][i] =  data;
		      stats[cur][ss][j][i] =  0;
		    }
		  else
		    {
		      int ao = stats[cur][avg][j][i];
		      stats[cur][avg][j][i] = stats[cur][avg][j][i] + (data - stats[cur][avg][j][i])/stats[cur][n][j][i];
		      stats[cur][ss][j][i] = stats[cur][ss][j][i] + (data-ao)*(data - stats[cur][avg][j][i]);
		    }		
		}
	    }
	}
      updatetime = timestamp;
    }
  if (timestamp - statstime >= MIN_TRAIN && training_done)
    {
      statstime = timestamp;
      cout<<"========================> Updating means "<<endl;
      for (int j = n; j <= ss; j++)
	for (int k = vol; k <= sym; k++)
	  {
	    // Move cur arrays into hist and zero down cur
	    memcpy (stats[hist][j][k], stats[cur][j][k], BRICK_DIMENSION * sizeof (double));
	    memset ((double*)stats[cur][j][k], 0, BRICK_DIMENSION * sizeof (double));
	  }
    }
}

/***********************************************************************/
void *
reset_transmit (void *passed_params)
{
  int error;
  while (1)
    {
      long curtime = 0;
      int fresh = 0;
      int error;
      if ((error = pthread_mutex_lock (&samples_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	}
      if ((error = pthread_mutex_lock (&cells_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}

      // Find timestamps that are not fresh
      for (map<long,cell>::iterator it=cells.begin(); it != cells.end(); it++)
	{
	  curtime = it->first;
	  if (it->second.fresh || fresh)
	    {
	      if (fresh == 0)
		{
		  int diff = curtime - firsttime;
		  cout<<"Reset "<<training_done<<" curtime "<<curtime<<" first "<<firsttime<<" diff "<<diff<<endl;
		  if(diff > MIN_TRAIN)
		    {
		      training_done = 1;
		      statstime = curtime;
		    }
		  fresh = 1;
		}
	      cells[it->first].fresh = 0;
	      continue;
	    }
	  if (!training_done)
	    {
	      // Collect data for training
	      for (int i=0;i<BRICK_DIMENSION;i++)
		{
		  for (int j=vol; j<=sym; j++)
		    {
		      int data;
		      if (j == vol)
			data = cells[it->first].databrick_p[i];				 
		      else
			data = cells[it->first].databrick_s[i];
		      // Update avg and ss
		      stats[hist][n][j][i] += 1;
		      if (stats[hist][n][j][i] == 1)
			{
			  stats[hist][avg][j][i] =  data;
			  stats[hist][ss][j][i] =  0;
			}		      
		      else
			{
			  int ao = stats[hist][avg][j][i];
			  stats[hist][avg][j][i] = stats[hist][avg][j][i] + (data - stats[hist][avg][j][i])/stats[hist][n][j][i];
			  stats[hist][ss][j][i] = stats[hist][ss][j][i] + (data-ao)*(data - stats[hist][avg][j][i]);
			}
		    }
		}
	      update_dst_arrays(it->first);
	    }
	  else
	    {
	      detect_attack(it->first);
	      update_dst_arrays(it->first);
	    }
	  cells.erase(it++);
	  samples.erase(curtime);
	}
      if ((error = pthread_mutex_unlock (&cells_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      if ((error = pthread_mutex_unlock (&samples_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}

      
      sleep(1);
    }
  pthread_exit (NULL);
}

/*************************************************************************/

#ifdef VERBOSE_SUPPORT
static int32_t thiszone;

#endif

/***************************************************************************/

void
printHelp (void)
{
  printf ("amon\n(C) 2015  Merit Network, Inc.\n\n");
  printf ("-h              Print this help\n");
  printf
    ("-r <inputfile>  Input PCAP, nfdump or flow-tools file; besides -f option, all other options ignored\n");
  printf ("-i <devices>    Comma-separated list of devices: ethX,ethY\n");
  printf ("-l <len>        Capture length\n");
  printf ("-g <core_id>    Bind to a core\n");
  printf ("-f <filter>     [BPF filter]\n");
  printf ("-p <poll wait>  Poll wait (msec)\n");
  printf ("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf ("-s              Use poll instead of active wait\n");
  printf ("-t              Trace ID e.g., 1\n");
  printf ("-c <server>     This is a client. By default it is server\n");
#ifdef VERBOSE_SUPPORT
  printf ("-v              Verbose\n");
#endif
}

/***************************************************************************/

inline int
bundlePoll ()
{
  int i;

  for (i = 0; i < num_devs; i++)
    {
      pfring_sync_indexes_with_kernel (pd[i]);
      pfd[i].events = POLLIN;
      pfd[i].revents = 0;
    }
  errno = 0;

  return poll (pfd, num_devs, poll_duration);
}

/****************************************************************************/

void
packetConsumer ()
{
  u_char *buffer;
  struct pfring_pkthdr hdr;
  memset (&hdr, 0, sizeof (hdr));
  int next = 0, hunger = 0;



  while (!do_shutdown)
    {

      if (pfring_is_pkt_available (pd[next]))
	{
	  if (pfring_recv
	      (pd[next], &buffer, 0, &hdr, 0 /* wait_for_packet */ ) > 0)
	    {
	      amonProcessingPcap(&hdr, buffer, time(0));
	      numPkts++;
	      numBytes += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */ ;
	    }

	  hunger = 0;
	}
      else
	hunger++;

      if (wait_for_packet && hunger >= num_devs)
	{
	  bundlePoll ();
	  hunger = 0;
	}

      next = (next + 1) % num_devs;
    }
}


int
main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  parse_config (&parms);                /* Read config file */
  char *devices = NULL, *dev = NULL, *tmp = NULL;
  char c, buf[32];
  u_char mac_address[6] = { 0 };
  int snaplen = parms.default_snaplen, rc;
  int bind_core = -1;
  u_int16_t cpu_percentage = 0;
  u_int32_t version;
  u_int32_t flags = 0;
  int i = 0;
  pthread_t thread_id;
  int retstatus;
  char *bpfFilter = NULL;
  char *pcap_in = NULL;
  struct bpf_program fcode;
  int ispcap = 0; /* Flag telling us the file format, pcap or nfdump/flow-tools */

  startTime.tv_sec = 0;
#ifdef VERBOSE_SUPPORT
  thiszone = gmt_to_local (0);
#endif

  while ((c = getopt (argc, argv, "hi:l:vsw:p:b:g:f:m:n:r:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'n':
	  interval=atoi(optarg);
	  break;
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'r':
	  pcap_in = strdup (optarg);
	  break;
	case 's':
	  wait_for_packet = 1;
	  break;
	case 'l':
	  snaplen = atoi (optarg);
	  break;
	case 'i':
	  devices = strdup (optarg);
	  break;
	case 'f':
	  bpfFilter = strdup (optarg);
	  break;
#ifdef VERBOSE_SUPPORT
	case 'v':
	  verbose = 1;
	  break;
#endif
	case 'b':
	  cpu_percentage = atoi (optarg);
	  break;
	case 'p':
	  poll_duration = atoi (optarg);
	  break;
	case 'g':
	  bind_core = atoi (optarg);
	  break;
	}
    }


  if (devices == NULL)
    devices = strdup (parms.default_device);
  
  srand (parms.seed);

  /* Data is not ready for reading */
  isready = 0;

  
  for (int i = 0; i < BRICK_DIMENSION; i++)
    {
      sprintf(filename,"%d.debug", i);
      debug[i].open(filename);
    }
  
  retstatus =
    pthread_create (&thread_id, NULL, reset_transmit, NULL);
  if (retstatus)
    {
      printf ("ERROR; return code from pthread_create() is %d\n",
	      retstatus);
      exit (-1);
    }
  
  char ebuf[256];
  u_char *p;
  struct pcap_pkthdr *h;
  /* This is going to be a pointer to input
     stream, either from PCAP or nfdump or flow-tools */
  pcap_t *pt;
  FILE* nf;
  struct pfring_pkthdr hdr;
  unsigned long long num_pcap_pkts = 0;      
  struct timeval beginning = { 0, 0 };

  /* Ready to start the reset and transmit helper thread */
  retstatus =
    pthread_create (&thread_id, NULL, reset_transmit, NULL);
  if (retstatus)
    {
      printf ("ERROR; return code from pthread_create() is %d\n",
	      retstatus);
      exit (-1);
    }
  
  /* libpcap functionality follows */
  if (pcap_in)
    {
      int isdir = 0;
      vector<string> tracefiles;
      struct stat s;
      if( stat(pcap_in,&s) == 0 )
	{
	  if(s.st_mode & S_IFDIR )
	    {
	      //it's a directory, read it and fill in 
	      //list of files
	      DIR *dir;
	      struct dirent *ent;
	      if ((dir = opendir (pcap_in)) != NULL) {
		/* print all the files and directories within directory */
		while ((ent = readdir (dir)) != NULL) {
		  tracefiles.push_back(string(pcap_in) + "/" + string(ent->d_name));
		}
		closedir (dir);
	      } else {
		cerr<<"Could not read directory "<<pcap_in<<endl;
		exit(1);
	      }	      
	      std::sort(tracefiles.begin(), tracefiles.end());
	    }
	  else if(s.st_mode & S_IFREG)
	    {
	      tracefiles.push_back(pcap_in);
	    }
	  else
	    exit(1);
	}
      else
	exit(1);

      // Go through tracefiles and read each one
      for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
      {
	const char* file = vit->c_str();
	cout<<"Trying to open file "<<file<<endl;
	memset (&hdr, 0, sizeof (hdr));
	
	pt = pcap_open_offline (file, ebuf);
	if (pt)
	  ispcap = 1;
	else
	  {
	    ispcap = 0;
	    char cmd[MAXLEN];
	    sprintf(cmd,"nfdump -r %s -o pipe 2>/dev/null", file);
	    nf = popen(cmd, "r");
	    /* Close immediately so we get the error code 
	       and we can detect if this is maybe flow-tools format */
	    int error = pclose(nf);
	    if (error == 64000)
	      {
		sprintf(cmd,"ft2nfdump -r %s | nfdump -r - -o pipe", file);
		nf = popen(cmd, "r");
		cout<<"Opened with ft2nfdump\n";
	      }
	    else
	      {
		nf = popen(cmd, "r");
	      }
	    if (!nf)
	      {
		fprintf(stderr,"Cannot open file %s for reading. Unknown format.\n", file);
		exit(1);
	      }
	  }
	if (ispcap)
	  {
	    int datalink = pcap_datalink (pt);
	    
	    if (datalink != DLT_EN10MB)
	      printf ("WARNING [pcap] Datalink not DLT_EN10MB (Ethernet).\n");
	    
	    if (bpfFilter != NULL)
	      {
		if (pcap_compile (pt, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0)
		  {
		    printf ("pcap_compile error: '%s'\n", pcap_geterr (pt));
		  }
		else
		  {
		    if (pcap_setfilter (pt, &fcode) < 0)
		      {
			printf ("pcap_setfilter error: '%s'\n",
				pcap_geterr (pt));
		      }
		  }
	      }
	  }
	else
	  {
	    cout<<"Filter with nfdump, unsupported\n";
	    /* Filter with nfdump, so far this is unsupported */
	  }
	if (ispcap)
	  {
	    while (1)
	      {
		int rc = pcap_next_ex (pt, &h, (const u_char **) &p);
		
		if (rc <= 0)
		  break;
		
		if (num_pcap_pkts == 0)
		  {
		    curTime = h->ts.tv_sec;
		    dbTime = 0;
		    beginning.tv_sec = h->ts.tv_sec;
		    beginning.tv_usec = h->ts.tv_usec;
		    printf ("First packet seen at %ld\n",
			    beginning.tv_sec * 1L);
		  }
		num_pcap_pkts++;
		
		memcpy (&hdr, h, sizeof (struct pcap_pkthdr));
		amonProcessingPcap(&hdr, p, h->ts.tv_sec);
	      }
	  }
	else
	  {
	    char line[MAX_LINE];
	    cout<<"Trying to read from "<<nf<<endl;
	    while (fgets(line, MAX_LINE, nf) != NULL)
	      {
		// Check that this is the line with a flow
		char tmpline[255];
		strcpy(tmpline, line);
		if (strstr(tmpline, "|") == NULL)
		  continue;
		strtok(tmpline,"|");
		strtok(NULL,"|");
		strtok(NULL,"|");
		char* tokene;
		char* token = strtok(NULL, "|");
		long epoch = strtol(token, &tokene, 10);
		token = strtok(NULL, "|");
		int msec = atoi(token);
		if (num_pcap_pkts == 0)
		  {
		    firsttime = epoch;
		    beginning.tv_sec = epoch;
		    beginning.tv_usec = msec*1000;
		    printf ("First packet seen at %ld\n",
			    beginning.tv_sec * 1L);
		  }
		num_pcap_pkts++;
		amonProcessingNfdump(line, epoch);
	      }
	  }     
	printf("Done with the file\n");
      }
    }
  return 0;			// Exit program
}
