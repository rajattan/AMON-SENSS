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
 * published by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
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
#include <sched.h>
#include <stdlib.h>
#include <sys/types.h>
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
#include <monetary.h>
#include <locale.h>
#include <pcap.h>
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <streambuf>

#include "pfring.h"
#include "pfutils.c"
#include "haship.h"
#include "haship.c"
#include "bm_structs.h"
#include <openssl/sha.h>

#define MAX_NUM_DEVS 64
#define MAXLEN 128
#define CONFIG_FILE "amon.config"
#define VERBOSE_SUPPORT
#define MAX_LINE 255
#define TCP 6
#define UDP 17
#define BUF_SIZE 1000
#define AR_LEN 30

int* delimiters;
sql::Connection *con;
sql::Statement *stmt;
sql::ResultSet *res;
int interval=3;

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

struct flow_p
{
  long time;
  int len;
  int oci;
  flow_t flow;
};
long buf_time = 0;
int buf_cnt = 0;
int buf_i = 0;
struct flow_p buffer[BUF_SIZE];
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

u_int8_t modality_type;            /* 0 for bytes, 1 for packets, 2 for 
				      outstanding connections */

unsigned int *P_bm;
unsigned int *P_bm_r;
unsigned int *P_bm_tmp;

flow_t *cand;		            /* array of candidate keys */
flow_t *cand_r;		            /* helper array for reading candidate keys */
flow_t *cand_tmp;	            /* tmp array used for swapping the above pointers */

long *count_d;		            /* array of counters */
long *count_r;		            /* helper array for reading counts */
long *count_tmp;	            /* tmp array used for swapping the above pointers */
int isready;
long dbTime = 0;
long curTime = 0;

//unsigned int *major_flags;	    /* flag indicating whether majority exists */
//unsigned int *major_flags_r;	    /* (helper for reading) flag indicating whether majority exists */
//unsigned int *major_flags_tmp;	    /* (tmp for swapping)  flag indicating whether majority exists */

unsigned int *databrick_p;	    /* databrick arrays - payload */
int *databrick_s;	            /* databrick arrays - symmetry */

pthread_mutex_t critical_section_lock = PTHREAD_MUTEX_INITIALIZER;

/* Make sure we don't fire if data is not ready */
pthread_mutex_t time_sync_lock = PTHREAD_MUTEX_INITIALIZER;

flow_t pqueue[HEAPSIZE];            /* Heap data structure (priority queue)*/
struct nlist *hashtab[HASHSIZE];    /* Hash table associated with the priority queue*/

struct passingThreadParams
{
        int caller_id;
        int callee_id;
};


struct conf_param {

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

//=====================================================================//
//===== Function to parse databrick string to convert into number =====//
//=====================================================================//

long *string_to_long_array(char *input, long *level)
{
    char *cp = strtok(input, ", ");
    if (cp == NULL) {
        return (long *) malloc(sizeof(long) * *level);
    }

    long my_index = -1;
    long n;
    if (sscanf(cp, "%ld", &n) == 1) {
        my_index = *level;
        *level += 1;
    }
    long *array = string_to_long_array(NULL, level);
    if (my_index >= 0) {
        array[my_index] = n;
    }
    return array;
}

//==========================================================//
//=================== Export Databricks to DB ==============//
//==========================================================//
void
export_to_db (unsigned int *databrick_p, int *databrick_s, long timestamp)
{
  // First check if there's any data to read and add to
  sql::Statement *stmt = con->createStatement();
  char query[256];
 
  sprintf(query, "SELECT * from records where timestamp=%ld",timestamp);
 
  sql::ResultSet* rset = stmt->executeQuery(query);
  int n = rset->rowsCount();
  if (n > 0)
    {
      // Read old data and add to it, then update
      while (rset->next()) {
	/* Access column data by alias or column name */
	char* token;
	string out = rset->getString("volume");
	unsigned int* outp = (unsigned int*) out.c_str();
	for (int i=0;i<BRICK_DIMENSION*BRICK_DIMENSION;i++)
	  databrick_p[i] += outp[i];
	out = rset->getString("symmetry");
	int* outs = (int*) out.c_str();
	for (int i=0;i<BRICK_DIMENSION*BRICK_DIMENSION;i++)
	  databrick_s[i] += outs[i];
      }
      try
	{
	  sql::PreparedStatement *pstmt;
	  pstmt = con->prepareStatement("UPDATE records set volume=?, symmetry=? where timestamp=?");
	  pstmt->setUInt(3, timestamp);
	  unsigned char* pChars = (unsigned char*) databrick_p;
	  DataBuf pbuf((char*)pChars, BRICK_DIMENSION*BRICK_DIMENSION*sizeof(unsigned int));
	  istream pstream(&pbuf);
	  pstmt->setBlob(1,&pstream);
	  pChars = (unsigned char*) databrick_s;
	  DataBuf sbuf((char*)pChars, BRICK_DIMENSION*BRICK_DIMENSION*sizeof(int));
	  istream sstream(&sbuf);
	  pstmt->setBlob(2,&sstream);
	  bool res = pstmt->execute();
	  pstmt->close();
	  delete pstmt;
	} catch (sql::SQLException &e) {
	cout << "# ERR: SQLException in " << __FILE__;
	cout << "# ERR: " << e.what();
	cout << " (MySQL error code: " << e.getErrorCode();
	cout << ", SQLState: " << e.getSQLState() << " )\n";
      }
    }
  else
    {
      try
	{
	  sql::PreparedStatement *pstmt;
	  pstmt = con->prepareStatement("INSERT into records (timestamp,volume,symmetry) values (?,?,?)");
	  pstmt->setUInt(1, timestamp);
	  cout << " TIMESTAMP " << timestamp << endl;
	  unsigned char* pChars = (unsigned char*) databrick_p;
	  DataBuf pbuf((char*)pChars, BRICK_DIMENSION*BRICK_DIMENSION*sizeof(unsigned int));
	  istream pstream(&pbuf);
	  pstmt->setBlob(2,&pstream);
	  pChars = (unsigned char*) databrick_s;
	  DataBuf sbuf((char*)pChars, BRICK_DIMENSION*BRICK_DIMENSION*sizeof(int));
	  istream sstream(&sbuf);
	  pstmt->setBlob(3,&sstream);
	  bool res = pstmt->execute();
	  pstmt->close();
	  delete pstmt;
	} catch (sql::SQLException &e) {
	cout << "# ERR: SQLException in " << __FILE__;
	cout << "# ERR: " << e.what();
	cout << " (MySQL error code: " << e.getErrorCode();
	cout << ", SQLState: " << e.getSQLState() << " )\n";
      }
    }
  stmt->close();
  delete rset;
  delete stmt;
}

/******************************************************************/

void
print_stats ()
{
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  u_int64_t diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  double thpt;
  int i = 0;
  unsigned long long absolute_recv = 0, absolute_drop = 0;
  
  printf("\n Inside print stats function \n");
  if (startTime.tv_sec == 0)
    {
      gettimeofday (&startTime, NULL);
      print_all = 0;
    }
  else
    print_all = 1;

  gettimeofday (&endTime, NULL);
  deltaMillisec = delta_time (&endTime, &startTime);

  for (i = 0; i < num_devs; i++)
    {
      if (pfring_stats (pd[i], &pfringStat) >= 0)
	{
	  absolute_recv += pfringStat.recv;
	  absolute_drop += pfringStat.drop;
	}
    }

  nBytes = numBytes;
  nPkts = numPkts;

  {
    thpt = ((double) 8 * nBytes) / (deltaMillisec * 1000);

    fprintf (stderr, "=========================\n"
	     "Absolute Stats: [%ld pkts rcvd][%ld pkts dropped]\n"
	     "Total Pkts=%ld/Dropped=%.1f %%\n",
	     (long) absolute_recv, (long) absolute_drop,
	     (long) (absolute_recv + absolute_drop),
	     absolute_recv == 0 ? 0 :
	     (double) (absolute_drop * 100) / (double) (absolute_recv +
							absolute_drop));
    fprintf (stderr, "%s pkts - %s bytes",
	     pfring_format_numbers ((double) nPkts, buf1, sizeof (buf1), 0),
	     pfring_format_numbers ((double) nBytes, buf2, sizeof (buf2), 0));

    if (print_all)
      fprintf (stderr, " [%s pkt/sec - %s Mbit/sec]\n",
	       pfring_format_numbers ((double) (nPkts * 1000) / deltaMillisec,
				      buf1, sizeof (buf1), 1),
	       pfring_format_numbers (thpt, buf2, sizeof (buf2), 1));
    else
      fprintf (stderr, "\n");

    if (print_all && (lastTime.tv_sec > 0))
      {
	deltaMillisec = delta_time (&endTime, &lastTime);
	diff = nPkts - lastPkts;
	bytesDiff = nBytes - lastBytes;
	bytesDiff /= (1000 * 1000 * 1000) / 8;

	fprintf (stderr, "=========================\n"
		 "Actual Stats: %llu pkts [%s ms][%s pps/%s Gbps]\n",
		 (long long unsigned int) diff,
		 pfring_format_numbers (deltaMillisec, buf1, sizeof (buf1),
					1),
		 pfring_format_numbers (((double) diff /
					 (double) (deltaMillisec / 1000)),
					buf2, sizeof (buf2), 1),
		 pfring_format_numbers (((double) bytesDiff /
					 (double) (deltaMillisec / 1000)),
					buf3, sizeof (buf3), 1));
      }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf (stderr, "=========================\n\n");
}

/**********************************************************************/

void
sigproc (int sig)
{
  static int called = 0;
  int i = 0;

  fprintf (stderr, "Leaving...\n");
  if (called)
    return;
  else
    called = 1;
  do_shutdown = 1;
  print_stats ();

  for (i = 0; i < num_devs; i++)
    pfring_close (pd[i]);

  fprintf(stderr, "In sigproc\n");
  exit (0);
}

/***********************************************************************/

void
my_sigalarm (int sig)
{
  if (do_shutdown)
    return;

  print_stats ();
  alarm (parms.alarm_sleep);
  signal (SIGALRM, my_sigalarm);
}

/************************************************************************/

static char hexc[] = "0123456789ABCDEF";

char *
etheraddr_string (const u_char * ep, char *buf)
{
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hexc[j];
  else
    *cp++ = '0';

  *cp++ = hexc[*ep++ & 0xf];

  for (i = 5; (int) --i >= 0;)
    {
      *cp++ = ':';
      if ((j = *ep >> 4) != 0)
	*cp++ = hexc[j];
      else
	*cp++ = '0';

      *cp++ = hexc[*ep++ & 0xf];
    }

  *cp = '\0';
  return (buf);
}

//=========================================================//
//========= A faster replacement for inet_ntoa() ==========//
//=========================================================//
char *
_intoa (unsigned int addr, char *buf, u_short bufLen)
{
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do
    {
      byte = addr & 0xff;
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	{
	  *--cp = byte % 10 + '0';
	  byte /= 10;
	  if (byte > 0)
	    *--cp = byte + '0';
	}
      *--cp = '.';
      addr >>= 8;
    }
  while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char *) (cp + 1);

  return (retStr);
}

/*************************************************************/

char *
intoa (unsigned int addr)
{
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return (_intoa (addr, buf, sizeof (buf)));
}
/*****************************************************************/
int hash(u_int32_t ip)
{
  struct in_addr in;
  in.s_addr = ip;
  char address[20];
  strcpy(address, inet_ntoa(in));
  unsigned char output[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, address, strlen(address));
  SHA256_Final(output, &sha256);

  /* Take the last few bytes and mod BRICK_DIMENSION */
  int rvalue = 0;
  for (int i=SHA256_DIGEST_LENGTH-4; i<SHA256_DIGEST_LENGTH; i++)
    rvalue = rvalue*256+(int)output[i];

  return rvalue % BRICK_DIMENSION;

}

/*****************************************************************/

void amonReprocess()
{
  int s_bucket = 0, d_bucket = 0;	    /* indices for the databrick */
  int error;
  unsigned int payload;

  for (int i=0; i<BUF_SIZE;i++)
    {
      flow_t flow = buffer[i].flow;
      long time = buffer[i].time;
      int len = buffer[i].len;
      int oci = buffer[i].oci;
      if (time != buf_time)                 /* ignore flows that are not in the current time slot */	
	continue;
      curTime = buf_time;
      if (dbTime == 0)
	dbTime = buf_time;
      // If data is very much out of order we may have
      // a "crippled" second. That is fine since we add
      // data to databricks in database
      if (curTime - dbTime >= interval)
	{
	  if (isready == 0)
	    {
	      int diff = curTime - dbTime;
	      printf("Ready to process time %ld curtime %ld diff %d\n", time, curTime, diff);
	      isready = 1;
	    }
	  else if(isready == 2)
	    {
	      isready = 0;
	      int diff = curTime - dbTime;
	      dbTime = curTime;
	      printf("Ready and done, lastTime is now %ld curTime %ld diff %d\n", dbTime, curTime, diff);
	    }
	}
      s_bucket = hash(flow.src); /* Jelena: should add  & mask */
      d_bucket = hash(flow.dst); /* Jelena: should add  & mask */

      int error;
      if ((error = pthread_mutex_lock (&critical_section_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      databrick_p[s_bucket * BRICK_DIMENSION + d_bucket] += len;	// add bytes to payload databrick
      databrick_s[s_bucket * BRICK_DIMENSION + d_bucket] += oci;	// add oci to symmetry databrick
      if ((error = pthread_mutex_unlock (&critical_section_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}			/*      Exiting Critical Section     */
    }
}

void
amonProcessing(flow_t flow, int len, long time, int oci)
{
  // Just insert data into buffer
  if (buf_i == BUF_SIZE-1)
    {
      amonReprocess();
      buf_i = 0;
      buf_cnt = 0;
      buf_time = 0;
    }
  buffer[buf_i].time = time;
  buffer[buf_i].len = len;
  buffer[buf_i].oci = oci;
  buffer[buf_i].flow = flow;
  buf_i++;
  if (buf_time == 0)
    {
      buf_time = time;
      buf_cnt = 1;
    }
  else if (buf_time != time)
    {
      buf_cnt--;
      if (buf_cnt == 0)
	{
	  buf_time = time;
	  buf_cnt = 1;
	}
    }
  else
    buf_cnt++;
}


void
amonProcessingNfdump (char* line, long time)
{
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  // Get start and end time of a flow
  char* tokene;
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
  int flags = atoi(line+delimiters[19]);
  pkts = atoi(line+delimiters[21]);
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
      if (flags & 16 > 0)
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
	{
	  oci = -1;
	  unsigned int tempsrc = flow.src;
	  flow.src = flow.dst;
	  flow.dst = tempsrc;
	  unsigned short tempsport = flow.sport;
	  flow.sport = flow.dport;
	  flow.dport = tempsport;
	}
      // request
      else if (flow.sport >= 1024 && flow.dport < 1024)
	oci = 1;
      // unknown, assume request
      else
	oci = 1;
    }
  else
    // unknown, assume request
    // we could fix this for ICMP trafic if type.code
    // is correct in data
    oci=1;
  amonProcessing(flow, bytes, end, oci);
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
	#if 0
      		printf ("[%s:%d %d", intoa (ntohl (ip.ip_src.s_addr)),
              	h->extended_hdr.parsed_pkt.l4_src_port, s_bucket);
      		printf ("-> %s:%d] \n", intoa (ntohl (ip.ip_dst.s_addr)),
              	h->extended_hdr.parsed_pkt.l4_dst_port);
	#endif


      flow.src = src_omega;
      flow.dst = dst_omega;
      flow.sport = h->extended_hdr.parsed_pkt.l4_src_port;
      flow.dport = h->extended_hdr.parsed_pkt.l4_dst_port;
      len = h->len;

      amonProcessing(flow, len, time, 0);
    }
}


/***********************************************************************/
void *
reset_transmit (void *passed_params)
{
  int error;
  while (1)
    {
      usleep(1000);
      if ((error = pthread_mutex_lock (&time_sync_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      /* Check if data is ready */
      if (!isready)
	{
	  if ((error = pthread_mutex_unlock (&time_sync_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }			/*      Exiting Critical Section     */
	}
      else
	{
	  isready = 2;   /* signal that we have started processing what is there */
	  // Standardize time
	  long mongoTime = int(dbTime / interval)*interval;
	  // Divide databrick items to get measures per second
	  for(int i=0; i<BRICK_DIMENSION*BRICK_DIMENSION; i++)
	    {
	      databrick_p[i] = int(databrick_p[i]/interval);
	      databrick_s[i] = int(databrick_s[i]/interval);
	    }
	  asm volatile ("":::"memory");
	  printf ("===============%ld======================\n", dbTime);
	  /*      Entering Critical Section     */
	  if ((error = pthread_mutex_lock (&critical_section_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }
	  
	  

	  if ((error = pthread_mutex_unlock (&time_sync_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }			/*      Exiting Critical Section     */


	  printf("\n Timestamp %ld \n",mongoTime);

	  /* Transmit databrick to MongoDB - centralized monitoring station */
	  /* Rajat, here we should send the mongoTime too, to the function. */
	  export_to_db (databrick_p, databrick_s, mongoTime);
	  /* Zero down databricks for next time */
	  memset ((unsigned int *) databrick_p, 0,
		  BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));
	  memset ((int *) databrick_s, 0,
		  BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));
	  /* End of mongodb part - this should go into a function */

	  
	  if ((error = pthread_mutex_unlock (&critical_section_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }			/*      Exiting Critical Section     */
	  printf ("=====================================================\n");
	}    
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
  printf ("-m              Modality type, 0 for bytes, 1 for\n");
  printf ("                packets, 2 for outstanding conns\n");
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

/***********************************************************************/


int
main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  parse_config (&parms);                /* Read config file */
  int h=hash(3477827584);
  cout<<"Hash is "<<h<<endl;

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
	  printf("Pcap in is %s\n", pcap_in);
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
	case 'm':
	  modality_type = atoi(optarg);
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
  
  sql::Driver *driver;
  
  
  /* Create a connection */
  driver = get_driver_instance();
  con = driver->connect(parms.db_client, parms.user, parms.pass);
  con->setSchema(parms.database);
  
  srand (parms.seed);

  /* Initialize AMON variables and structs */
  /* Define the pointers to the sketch arrays */
  databrick_p = (unsigned int *) malloc(BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));
  databrick_s = (int *) malloc(BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));
  memset ((unsigned int *) databrick_p, 0,
	  BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));
  memset ((int *) databrick_s, 0,
	  BRICK_DIMENSION * BRICK_DIMENSION * sizeof (unsigned int));

  /* Data is not ready for reading */
  isready = 0;
  
  /* libpcap functionality follows */
  if (pcap_in)
    {
      char ebuf[256];
      u_char *p;
      struct pcap_pkthdr *h;
      /* This is going to be a pointer to input
	 stream, either from PCAP or nfdump or flow-tools */
      pcap_t *pt;
      FILE* nf;
      
      unsigned long long num_pcap_pkts = 0;
      struct timeval beginning = { 0, 0 };
      struct pfring_pkthdr hdr;
      memset (&hdr, 0, sizeof (hdr));

      pt = pcap_open_offline (pcap_in, ebuf);
      if (pt)
	ispcap = 1;
      else
	{
	  ispcap = 0;
	  char cmd[300];
	  sprintf(cmd,"nfdump -r %s -o pipe 2>/dev/null", pcap_in);
	  nf = popen(cmd, "r");
	  /* Close immediately so we get the error code 
	     and we can detect if this is maybe flow-tools format */
	  int error = pclose(nf);
	  if (error == 64000)
	    {
	      //sprintf(cmd,"ft2nfdump -r %s | nfdump -r - -o 'fmt:%%ts %%te %%pr %%sap -> %%dap %%flg %%pkt %%byt %%fl'", pcap_in);
	      sprintf(cmd,"ft2nfdump -r %s | nfdump -r - -o pipe", pcap_in);
	      nf = popen(cmd, "r");
	    }
	  else
	    {
	      nf = popen(cmd, "r");
	    }
	  if (!nf)
	    {
	      fprintf(stderr,"Cannot open file %s for reading. Unknown format.\n", pcap_in);
	      exit(1);
	    }
	  else
	    {
	      /* Remove first line, it is the header */
	      char line[MAX_LINE];
	      fgets(line, MAX_LINE, nf);
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
	/* Filter with nfdump, so far this is unsupported */
      }
    /* Ready to start the reset and transmit helper thread */
    int retstatus =
      pthread_create (&thread_id, NULL, reset_transmit, NULL);
    if (retstatus)
      {
	printf ("ERROR; return code from pthread_create() is %d\n",
		retstatus);
	exit (-1);
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
		curTime = epoch;
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



      return 0;			// Exit program
    }

  /* PF_RING functionality follows */
  bind2node (bind_core);

  if (wait_for_packet && (cpu_percentage > 0))
    {
      if (cpu_percentage > 99)
	cpu_percentage = 99;
      pfring_config (cpu_percentage);
    }

  dev = strtok_r (devices, ",", &tmp);
  while (i < MAX_NUM_DEVS && dev != NULL)
    {
      flags |= PF_RING_PROMISC;
      flags |= PF_RING_DNA_SYMMETRIC_RSS;
#if 0			
      flags |= PF_RING_LONG_HEADER;
#endif
      pd[i] = pfring_open (dev, snaplen, flags);

      if (pd[i] == NULL)
	{
	  fprintf (stderr,
		   "pfring_open error [%s] (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n",
		   strerror (errno), dev);
	  return (-1);
	}

      if (i == 0)
	{
	  pfring_version (pd[i], &version);

	  printf ("Using PF_RING v.%d.%d.%d\n",
		  (version & 0xFFFF0000) >> 16,
		  (version & 0x0000FF00) >> 8, version & 0x000000FF);
	}

      pfring_set_application_name (pd[i], (char*)"amon");

      printf ("Capturing from %s", dev);
      if (pfring_get_bound_device_address (pd[i], mac_address) == 0)
	printf (" [%s]\n", etheraddr_string (mac_address, buf));
      else
	printf ("\n");

      printf ("# Device RX channels: %d\n",
	      pfring_get_num_rx_channels (pd[i]));

      if (bpfFilter != NULL)
	{
	  rc = pfring_set_bpf_filter (pd[i], bpfFilter);
	  if (rc != 0)
	    printf ("pfring_set_bpf_filter(%s) returned %d\n", bpfFilter, rc);
	  else
	    printf ("Successfully set BPF filter '%s'\n", bpfFilter);
	}
	
      if ((rc = pfring_set_socket_mode (pd[i], recv_only_mode)) != 0)
	fprintf (stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

      pfd[i].fd = pfring_get_selectable_fd (pd[i]);

      pfring_enable_ring (pd[i]);

      dev = strtok_r (NULL, ",", &tmp);
      i++;
    }
  num_devs = i;

  signal (SIGINT, sigproc);
  signal (SIGTERM, sigproc);
  signal (SIGINT, sigproc);

#ifdef VERBOSE_SUPPORT
  if (!verbose)
    {
#endif
      signal (SIGALRM, my_sigalarm);
      alarm (parms.alarm_sleep);
#ifdef VERBOSE_SUPPORT
    }
#endif

  if (bind_core >= 0)
    bind2core (bind_core);

  retstatus = pthread_create (&thread_id, NULL, reset_transmit, NULL);
  if (retstatus)
    {
      printf ("ERROR; return code from pthread_create() is %d\n", retstatus);
      exit (-1);
    }

  packetConsumer ();

  alarm (0);
  sleep (1);

  for (i = 0; i < num_devs; i++)
    pfring_close (pd[i]);

  return (0);
}
