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
#include <fstream>
#include <sched.h>
#include <stdlib.h>
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

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <streambuf>

#include "pfring.h"
#include "pfutils.c"
#include "utils.h"

int* delimiters;
sql::Connection *con;
sql::Statement *stmt;
sql::ResultSet *res;
int interval=3;
int reporters=0;
int reported=0;
map<int, int> adms;
fd_set readset, writeset;

int isready;
long dbTime = 0;
long curTime = 0;


char* server = NULL;
int is_server = 1;
int training_done = 0;
int sockfd = 0;

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
};


vector <flow_p> pool[BRICK_DIMENSION];            /* for attack signatures */
struct indic indicators[BRICK_DIMENSION];         /* to signal when there is an attack */
int ii=0;

map<long,cell> cells;
map<int,long> lasttime;
map<long,map<int, sample>> samples;
map<int,map<sig_b,stat_r>> signatures;
long smallesttime = 0;
long firsttime = 0;
long updatetime = 0;
long statstime = 0;
int traceid = 0;
char im[BIG_MSG];
int imlen = 0;
int admsg = 0;
int seqnum = 0;

pthread_mutex_t critical_section_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t admsg_lock = PTHREAD_MUTEX_INITIALIZER;
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
	    {
	      //cout<<"Flow for line "<<samples[t][index].raw[i-1]<<" oci "<<f.oci<<" sign diff than "<<sgn(aoci)<<endl;
	      continue;
	    }
	  //cout<<"Keeping flow for line "<<samples[t][index].raw[i-1]<<" oci "<<f.oci<<" sign same as "<<sgn(aoci)<<endl;
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
	      cout<<"s = "<<s<<" key=from "<<key.src<<":"<<key.sport<<" "<<key.dst<<":"<<key.dport<<" "<<(int)key.proto<<" v="<<sigs[s][key].vol<<" oci="<<sigs[s][key].oci<<endl;
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
		  cout<<"Passed filter "<<index<<" from "<<k.src<<":"<<k.sport<<" "<<k.dst<<":"<<k.dport<<" "<<(int)k.proto<<" v="<<sit->second.vol<<" oci="<<sit->second.oci<<endl;

		  samples[t][index].signatures[sit->first] = {sit->second.vol, sit->second.oci, (double)sit->second.vol/vol, (double)sit->second.oci/oci};	     
		}
	    }
	}
    }
  return t;
}


//==========================================================//
//=================== Export Databricks to DB ==============//
//==========================================================//
void
export_to_db (long timestamp)
{

  // Connect if you haven't already
  if (!sockfd)
    {
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
      struct hostent *he;
      struct in_addr **addr_list;
      struct sockaddr_in address;

      if(inet_addr(server) == -1)
	{
	  //resolve the hostname, its not an ip address
	  if ((he = gethostbyname(server)) == NULL)
	    {
	      //gethostbyname failed
	      herror("gethostbyname");
	      cout<<"Failed to resolve hostname\n";
	      return;
	    }
	       
	    //Cast the h_addr_list to in_addr , since h_addr_list also has the ip address in long format only
	    addr_list = (struct in_addr **) he->h_addr_list;
	    
	    for(int i = 0; addr_list[i] != NULL; i++)
	      {
		//strcpy(ip , inet_ntoa(*addr_list[i]) );
		address.sin_addr = *addr_list[i];
		break;
	      }
	}
      else
	{
	  address.sin_addr.s_addr = inet_addr(server);
	}
      address.sin_family = AF_INET;
      address.sin_port = htons(AMON_PORT);

      //Connect to remote server
      if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
	  perror("connect failed. Error");
	}
      char OK[3];
      // Wait for server to be ready
      recv(sockfd, OK, 3, 0);
    }
      
  // Go through cells and see which ones are ready. These are the ones that are
  // less than timestamp
  
  do{
    FD_CLR(sockfd, &readset);
    FD_CLR(sockfd, &writeset);
    FD_SET(sockfd, &readset);
    FD_SET(sockfd, &writeset);
  } while(select(sockfd + 1, &readset, &writeset, NULL, NULL) == -1);
  
  /* Am I ready to read or to write? */
  if (FD_ISSET(sockfd, &readset)) {
    /* Got a message from socket, let's see what it is */
    char message[BRICK_DIMENSION*sizeof(int)];
    int n = recv(sockfd, message, BRICK_DIMENSION*sizeof(int), 0);
    if (n > 0)
      {
	cout<<" Received message about attack "<<n<<endl;
	indic* attacks_detected = (indic*) message;
	int si = 0;
	int len = 0;
	char *asigs = (char*) malloc(BIG_MSG);
	// Format for the signature message is S, followed by bin, followed by signatures, followed by |
    // bin, signatures, etc. If there is no signature send just bin |
	asigs[0]='S';
	int ai=1;
	for (int i=0;i<n/sizeof(indic); i++)
	  {
	    cout<<"Attack detected in bin "<<attacks_detected[i].bin
		<<" at time "<<attacks_detected[i].timestamp<<" oci "<<attacks_detected[i].oci<<endl;
	    int bin = attacks_detected[i].bin;
	    memcpy(asigs+ai, (char*) &bin, sizeof(int));
	    ai += sizeof(int);
	    // Find closest timestamp and calculate signatures
	    long t = calcSignature(attacks_detected[i].timestamp, attacks_detected[i].bin, attacks_detected[i].oci);
	    cout<<"Closest timestamp "<<t<<endl;
	    // How many signatures?
	    int hm=samples[t][bin].signatures.size();
	    memcpy(asigs+ai, (char*) &hm, sizeof(int));
	    ai += sizeof(int);
	    for(map<sig_b,stat_r>::iterator sit=samples[t][bin].signatures.begin(); sit != samples[t][bin].signatures.end(); sit++)
	      {
		memcpy(asigs+ai, (char*) &sit->first, sizeof(sig_b));
		ai += sizeof(sig_b);
		memcpy(asigs+ai, (char*) &sit->second, sizeof(stat_r));
		ai += sizeof(stat_r);
		cout<<"From "<<sit->first.src<<":"<<sit->first.sport<<" "<<
		  sit->first.dst<<":"<<sit->first.dport<<" v="<<sit->second.vol<<"("<<sit->second.volp<<") o="
		    <<sit->second.oci<<"("<<sit->second.ocip<<")"<<endl;
	      }
	  }
	// Now send signatures to the server for each attack 
	if(send(sockfd, asigs, ai, 0) < 0)
	  {
	    perror("Send failed : ");
	    return;
	  }
	else
	  cout<<"Sent "<<ai<<" characters to server\n";
	// Now or later delete signatures and samples for some timestamps
      }
  }
  else if (FD_ISSET(sockfd, &writeset)) {
    
    for (map<long,cell>::iterator it=cells.begin(); it != cells.end(); )
      {
	if (it->first >= timestamp)
	{
	  return;
	}
	int expected_size = 1+2*sizeof(int)+
	  sizeof(long)+BRICK_DIMENSION*(sizeof(unsigned int)+sizeof(int));
	unsigned char* message = (unsigned char*) malloc(expected_size);
	int mi=0;
	message[mi] = 'R';
	mi++;
	memcpy(message+mi, (unsigned char*)&traceid, sizeof(int));
	mi += sizeof(int);
	memcpy(message+mi, (unsigned char*)&seqnum, sizeof(seqnum));
	mi += sizeof(int);
	memcpy(message+mi, (unsigned char*)&it->first, sizeof(long));
	mi += sizeof(long);
	memcpy(message+mi, (unsigned char*) it->second.databrick_p, BRICK_DIMENSION*sizeof(unsigned int));
	mi += BRICK_DIMENSION*sizeof(unsigned int);
	memcpy(message+mi, (unsigned char*) it->second.databrick_s, BRICK_DIMENSION*sizeof(int));
	mi += BRICK_DIMENSION*sizeof(int);
	if(send(sockfd, message, mi, 0) < 0)
	  {
	    perror("Send failed : ");
	    return;
	  }
	else
	  cout<<"Sent "<<mi<<" to server for timestamp "<<it->first<<" seqnum "<<seqnum<<"\n";
	seqnum++;
	cells.erase(it++);
      }
  }
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

void addSample(int index, flow_p f, char* line, long i)
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
	  //memcpy(samples[i][index].raw[j],line,strlen(line));
	}
    }
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
  // Standardize time
  start = int(start / interval)*interval;
  end = int(end / interval)*interval;
  for (long i = start; i <= end; i+= interval)
    {
        int error;
	if ((error = pthread_mutex_lock (&critical_section_lock)))
	  {
	    fprintf (stderr,
		     "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		     error);
	    exit (-1);
	  }

      if (cells.find(i) == cells.end())
	{
	  //cout<<"Inserted cell for "<<i<<endl;
	  cells.insert(pair<long,cell>(i,c));
	}
      //cout<<i<<"prev src bucket "<<s_bucket<<" oci "<<cells[i].databrick_s[s_bucket]<<" dst bucket "<<d_bucket<<" len "<<cells[i].databrick_p[d_bucket]<<" oci "<<cells[i].databrick_s[d_bucket] <<endl;
      cells[i].databrick_p[d_bucket] += len;	// add bytes to payload databrick for dst
      cells[i].databrick_s[d_bucket] += oci;	// add oci to symmetry databrick for dst
      cells[i].databrick_s[s_bucket] -= oci;	// subtract oci from symmetry databrick for src
      //cout<<i<<" src bucket "<<s_bucket<<" oci "<<cells[i].databrick_s[s_bucket]<<" dst bucket "<<d_bucket<<" len "<<cells[i].databrick_p[d_bucket]<<" oci "<<cells[i].databrick_s[d_bucket] <<endl;
      flow_p f={start, end, len, oci, flow};
      addSample(d_bucket, f, line, i);

      if ((error = pthread_mutex_unlock (&critical_section_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	} 
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


ofstream debug[BRICK_DIMENSION];
int is_attack[BRICK_DIMENSION];
int is_abnormal[BRICK_DIMENSION]; 
ofstream outfiles[BRICK_DIMENSION];


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
  if (timestamp >= smallesttime || timestamp <= updatetime)
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

      debug[i] <<records[ri][i].timestamp<<" "<<records[ri][i].avgv<<" ";
      debug[i] <<records[ri][i].stdv<<" "<<records[ri][i].valv<<" ";
      debug[i] <<records[ri][i].avgs<<" "<<records[ri][i].stds<<" ";
      debug[i] <<records[ri][i].vals<<" "<<is_attack[i]<<endl;
      
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
	      /* Update indicators */
	      int error;
	      if ((error = pthread_mutex_lock (&indicator_lock)))
		{
		  fprintf (stderr,
			   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
			   error);
		  exit (-1);
		}
	      indicators[ii].bin=i;
	      indicators[ii].timestamp=timestamp;
	      indicators[ii].oci=cells[timestamp].databrick_s[i];
	      ii++;
	      if ((error = pthread_mutex_unlock (&indicator_lock)))
		{
		  fprintf (stderr,
			   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
			   error);
		  exit (-1);
		}
	      cout <<" Attack detected in destination bin " << i << " time " << timestamp <<" mean "<<avgv<<" + 5*"<< stdv<<" < "<<cells[timestamp].databrick_p[i]<<" and "<<avgs<<" +- 5*"<<stds<<" inside "<<cells[timestamp].databrick_s[i]<<" flag "<<is_attack[i]<<endl;
	      /* Dump records into a file */
	      ofstream out;
	      out.open("alerts.txt", std::ios_base::app);
	      float volume = float(cells[timestamp].databrick_p[i])*8/1024/1024/1024;
	      out << "START "<<i<<" "<<timestamp<<" vol "<<volume<<" Gbps"<<endl;
	      out.close();
	      char filename[MAXLEN];
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
	      cout <<" Attack has stopped in destination bin "<< i << " time " << timestamp << endl;
	      ofstream out;
	      out.open("alerts.txt", std::ios_base::app);
	      out << "STOP "<<i<<" "<<timestamp<<endl;
	      out.close();
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
    {
      return;
    }
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
      sleep(1);
      if (is_server)
	{
	  int diff = smallesttime - statstime;

	  cout<<"Reset "<<training_done<<" smallesttime "<<smallesttime<<" stats "<<statstime<<" diff "<<diff<<endl;
	  if (!training_done)
	    {
	      // Find timestamps smaller than the smallest one
	      for (map<long,cell>::iterator it=cells.begin(); it != cells.end(); it++)
		{
		  long curtime = it->first;
		  if (it->first < smallesttime)
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
		}
	      int diff = smallesttime - firsttime;
	      if(diff > MIN_TRAIN)
		{
		  training_done = 1;
		  statstime = smallesttime;
		}
	    }
	  else
	    {
	      cout<<"Detecting attacks"<<endl;
	      // Find timestamps smaller than the smallest one
	      for (map<long,cell>::iterator it=cells.begin(); it != cells.end(); it++)
		{
		  if (it->first < smallesttime)
		    {
		      detect_attack(it->first);
		      update_dst_arrays(it->first);
		    }
		}
	    }

	}
      else
	{
	  int error;
	  if ((error = pthread_mutex_lock (&critical_section_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }
	  // Standardize time
	  long mongoTime = int(dbTime / interval)*interval;
      
	  //cout<<"Exporting, map size "<<cells.size()<<" time "<<mongoTime<<endl;

	  // Calculate signatures if any
	  export_to_db (mongoTime);
	  
	  buf_time = 0;
	  if ((error = pthread_mutex_unlock (&critical_section_lock)))
	    {
	      fprintf (stderr,
		       "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		       error);
	      exit (-1);
	    }			/*      Exiting Critical Section     */
	  
	  //cout<<"Returned from export, map size "<<cells.size()<<" time "<<mongoTime<<endl;
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

/***********************************************************************/

void *connection_handler(void *newsock)
{
  //Get the socket descriptor
  int sock = *(int*)newsock;
  int read_size;
  int expected_size = 2*sizeof(int)+sizeof(long)+
    BRICK_DIMENSION*(sizeof(unsigned int)+sizeof(int));
  unsigned char* message = (unsigned char*)malloc(BIG_MSG);
  int message_start = 0;

  while(!isready)
    {
      sleep(1);
    }
  //Send a GO message to client
  message[0] = 'G';
  message[1] = 'O';
  if(send(sock, message, 2, 0) < 0)
    {
      perror("Send failed : ");
      return 0;
    }
  else
    {
      cout<<"Sock "<<sock<<" sent message to client\n";
    }
  //Receive a message from client
  while (1)
    {
  while((read_size = recv(sock, message+message_start, BIG_MSG-message_start, 0)) > 0 )
    {
      cout<<"Received message size "<<read_size<<" expected "<<expected_size<<endl;
      unsigned char* mptr = message;
      while(mptr < message+read_size+message_start)
	{
	  cout << "Left to read "<<(message+message_start+read_size-mptr)<<" first is "<<*mptr<<endl;
	  // Is this a signature message or report?
	  if (*mptr == 'S')
	    {
	      cout<<" Got signature message "<<endl;
	      mptr++;
	      // Get signatures out
	      int bin;
	      memcpy(&bin, mptr, sizeof(int));
	      cout<<" For bin "<<bin<<endl;
	      mptr += sizeof(int);
	      // How many signatures are there?
	      int hm;
	      memcpy(&hm, mptr, sizeof(int));
	      mptr += sizeof(int);
	      cout << "Signatures "<<hm<<endl;
	      // Check if we have a complete message or not
	      int left = message+read_size+message_start-mptr;
	      if (hm*(sizeof(sig_b)+sizeof(stat_r)) > left && left > 0);
		{
		  // Prepare to receive more data to patch the segment
		  unsigned char* tmp = (unsigned char*) malloc(BIG_MSG);
		  tmp[0] = 'S';
		  memcpy(tmp+1, &hm, sizeof(int));
		  memcpy(tmp+sizeof(int)+1, mptr, message+read_size+message_start-mptr);
		  delete(message);
		  message = tmp;
		  message_start = left + 1 + sizeof(int);
		  cout<<"Message too short, start "<<message_start<<endl;
		  break;
		}
	      ofstream osig;
	      char filename[MAXLEN];
	      sprintf(filename,"sig.%d", bin);
	      osig.open(filename, std::ios_base::app);
	      
	      for (int j=0; j<hm;j++)
		{
		  map<sig_b, stat_r> m;
		  sig_b s={0,0,0,0};
		  stat_r r={0,0,0,0};
		  if (signatures.find(bin) == signatures.end())
		    signatures.insert(pair<int, map<sig_b,stat_r>>(bin,m));
		  memcpy(&s, mptr, sizeof(sig_b));
		  mptr += sizeof(sig_b);
		  memcpy(&r, mptr, sizeof(stat_r));
		  mptr += sizeof(stat_r);
		  if (signatures[bin].find(s) == signatures[bin].end())
		    signatures[bin].insert(pair<sig_b,stat_r>(s,r));
		  else
		    {
		      signatures[bin][s].vol += r.vol;
		      signatures[bin][s].oci += r.oci;
		      signatures[bin][s].volp += r.volp;
		      signatures[bin][s].ocip += r.ocip;
		    }
		  cout<<bin<<" "<<s.src<<":"<<s.sport<<" "<<s.dst<<":"<<s.dport<<(int)s.proto<<" v="<<
		    signatures[bin][s].vol<<"("<<signatures[bin][s].volp<<") o="
		      <<signatures[bin][s].oci<<"("<<signatures[bin][s].ocip<<")"<<endl;
		}
	      /* Find the best signature */
	      sig_b bestsig = {0,0,0,0};
	      int vol = 0;
	      int oci = 0;
	      for (map<sig_b,stat_r>::iterator sit = signatures[bin].begin(); sit != signatures[bin].end(); sit++)
		if (abs(signatures[bin][sit->first].oci) > abs(oci) ||
		    (signatures[bin][sit->first].oci == oci && bettersig(sit->first, bestsig)))
		  {
		    bestsig = sit->first;
		    vol = sit->second.vol;
		    oci = sit->second.oci;
		  }
	      cout<<"Best "<<bin<<" "<<printsignature(bestsig)<<" v="<<vol<<" o="<<oci<<endl;
	      osig<<printsignature(bestsig)<<endl;
	      osig.close();
	    }
	  else if (*mptr == 'R')
	    {
	      mptr++;
	      // Check if we have a complete message or not
	      int left = message+read_size+message_start-mptr;
	      cout <<"Left "<<left<<" expected "<<expected_size<<endl;
	      if (expected_size > left && left > 0)
		{
		  // Prepare to receive more data to patch the segment
		  unsigned char* tmp = (unsigned char*) malloc(BIG_MSG);
		  tmp[0] = 'R';
		  memcpy(tmp+1, mptr, message+read_size+message_start-mptr);
		  delete(message);
		  message = tmp;
		  message_start = left+1;
		  cout<<"Message too short, start "<<message_start<<endl;
		  break;
		}
	      int traceid;
	      int tseq;
	      long timestamp;
	      memcpy((unsigned char*) &traceid, mptr, sizeof(int));
	      mptr += sizeof(int);
	      memcpy((unsigned char*) &tseq, mptr, sizeof(int));
	      mptr += sizeof(int);
	      memcpy((unsigned char*) &timestamp, mptr, sizeof(long));
	      mptr += sizeof(long);
	      cout<<" Got report message, reporter "<<traceid<<" seqnum "<<tseq <<" time "<<timestamp<<" training done? "<<training_done<<endl;
	      cell c;
	      memcpy(c.databrick_p, mptr,
		 BRICK_DIMENSION*sizeof(unsigned int));
	      mptr += BRICK_DIMENSION*sizeof(unsigned int);
	      memcpy(c.databrick_s, mptr,
		     BRICK_DIMENSION*sizeof(int));
	      mptr += BRICK_DIMENSION*sizeof(int);
	      if (lasttime.find(traceid) == lasttime.end())
		lasttime[traceid] = timestamp;
	      if (timestamp > lasttime[traceid])
		{
		  lasttime[traceid] = timestamp;
		  if (firsttime == 0)
		    firsttime = timestamp;
		  smallesttime = timestamp;
		  for (map<int,long>::iterator lt=lasttime.begin(); lt != lasttime.end(); lt++)
		    {
		      if (lt->second < smallesttime)
			{
			  cout<<"Smallest time for "<<traceid<<" is "<<lt->second<<endl;
			  smallesttime = lt->second;
			}		      
		    }
		  int diff = smallesttime - firsttime;
		  cout<<"Smallest time "<<smallesttime<<" first time "<<firsttime<<" diff "<<diff<<endl;
		}
	      if (cells.find(timestamp) == cells.end())
		{
		  //cout<<"Inserted cell for "<<timestamp<<endl;
		  cells.insert(pair<long,cell>(timestamp,c));
		}
	      else
		for(int i=0; i<BRICK_DIMENSION;i++)
		  {
		    cells[timestamp].databrick_p[i] += c.databrick_p[i];
		    cells[timestamp].databrick_s[i] += c.databrick_s[i];
		  }
	    }
	  else
	    {
	      cout <<"First letter of message is "<<*mptr<<endl;
	      mptr++;
	    }
	}
      int error;
      if ((error = pthread_mutex_lock (&admsg_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      /* Is there attack detection message ready to send? */
      if (admsg > 0 && adms[sock] == 0)
	{
	  if(send(sock, im, imlen, 0) < 0)
	    {
	      perror("Send failed : ");
	      return 0;
	    }
	  else
	    cout<<"Sent attack detected message to "<<sock<<endl;
	  adms[sock] = 1;
	  admsg--;
	  /* Reset all socks */
	  if (admsg == 0)
	    for (map<int,int>::iterator ait=adms.begin(); ait != adms.end(); ait++)
	      adms[ait->first] = 0;
	}
      if ((error = pthread_mutex_unlock (&admsg_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      /* See if there is an attack and we have finished sending notification about prior attacks */
      if ((error = pthread_mutex_lock (&indicator_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      if (ii > 0 && admsg == 0)
	{
	  // get indicators in message and send out
	  memcpy(im, (char*) indicators, ii*sizeof(struct indic));
	  imlen = ii*sizeof(struct indic);
	  ii = 0;
	  admsg = reporters;	  
	}
      if ((error = pthread_mutex_unlock (&indicator_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}	 
      usleep(1);
    }
  cout<<"Read size "<<read_size<<endl;
    }
  reported--;
  adms.erase(sock);
  cout<<"Closing socket "<<sock<<" reporters now "<<reported<<endl;
  close(sock);
  return 0;
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

  while ((c = getopt (argc, argv, "hi:l:vsw:p:b:g:f:m:n:r:t:c:a:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'a':
	  reporters=atoi(optarg);
	  break;
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
	case 't':
	  traceid = atoi (optarg);
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
	case 'c':
	  server = strdup(optarg);
	  is_server = 0;
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

  /* Data is not ready for reading */
  isready = 0;

  /* Is this client or server */
  if (is_server)
    {
      for (int i = 0; i < BRICK_DIMENSION; i++)
	{
	  char filename[MAXLEN];
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
      
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
      int reuse = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		     (const char*)&reuse, sizeof(reuse)) < 0)
	perror("setsockopt(SO_REUSEADDR) failed");
      
#ifdef SO_REUSEPORT
      if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
		     (const char*)&reuse, sizeof(reuse)) < 0)
	perror("setsockopt(SO_REUSEPORT) failed");
#endif
      struct sockaddr_in address;
      int addrlen = sizeof(address);
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons(AMON_PORT);
      pthread_t thread_id;

      if (bind(sockfd, (struct sockaddr *)&address,
	       sizeof(address))<0)
	{
	  perror("bind failed");
	  exit(1);
	}
      if (listen(sockfd, BACKLOG) < 0)
	{
	  perror("listen");
	  exit(EXIT_FAILURE);
	}
      while(1)
	{
	  int newsock;
	  if ((newsock = accept(sockfd, (struct sockaddr *)&address,
				    (socklen_t*)&addrlen))<0)
	    {
	      perror("accept");
	      exit(EXIT_FAILURE);
	    }
	  smallesttime = 0;
	  reported++;
	  adms.insert(pair<int, int>(newsock,0));
	  cout<<"Accepted at address "<<address.sin_addr.s_addr<<" reporters "<<reporters<<" reported "<<reported<<endl;
	  if (reported == reporters)
	    isready = 1;
	  if(pthread_create( &thread_id, NULL,  connection_handler, (void*) &newsock) < 0)
	    {
	      perror("could not create thread");
	      return 1;
	    }
	}
    }
  else
    {
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

      /* libpcap functionality follows */
      if (pcap_in)
	{
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
	}
      /* Ready to start the reset and transmit helper thread */
      retstatus =
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
}
