/*
#
# Copyright (C) 2018 University of Southern California.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
*/

#include <signal.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sched.h>
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
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <cmath>

#include <dirent.h>

/* MySQL includes
#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
*/

#include "utils.h"

#define BILLION 1000000000L

using namespace std;

// We store delimiters in this array
int* delimiters;

// Something like strtok but it doesn't create new
// strings. Instead it replaces delimiters with 0
// in the original string
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

// Variables/structs needed for detection
struct cell
{
  unsigned int databrick_p[BRICK_DIMENSION];	 // databrick volume
  int databrick_s[BRICK_DIMENSION];	         // databrick symmetry 
  unsigned int wfilter_p[BRICK_DIMENSION];	 // volume w filter 
  int wfilter_s[BRICK_DIMENSION];	         // symmetry w filter 
  int fresh;
};
// How many service ports are there
int numservices = 0;
// How many local prefixes are there
int numprefs = 0;
// Save all flows for a given time slot
map<long, time_flow*> timeflows;

// These are the bins where we store stats
cell cells[QSIZE];
int cfront = 0;
int crear = 0;
bool cempty = true;

// Samples of flows for signatures
sample samples;

// Signatures we devised for each bin
map<int,stat_f> signatures;
// We remember all time slots here and
// do statistics update when we are sure
// that the time slot did not have an attack
vector<long> times;

// Save some stats about each bin if verbose bit is set
// This helps later with debugging
ofstream debug[BRICK_DIMENSION];
// Is the bin abnormal or not
int is_abnormal[BRICK_DIMENSION];
// Did we detect an attack in this bin
int is_attack[BRICK_DIMENSION];
// Did we report an attack in this bin
int reported[BRICK_DIMENSION];
// How effective is our filtering
double effective[BRICK_DIMENSION];
// How many attacks are we filtering currently
int isfiltered = 0;

// Did we complete training
bool training_done = false;
int trained = 0;

// Current time
long curtime = 0;

// Verbose bit
int verbose = 0;

long firsttime = 0;       // Beginning of trace 
long freshtime = 0;       // Where we last ended when processing data 
long firsttimeinfile = 0; // First time in the current file 
long updatetime = 0;      // Time of last stats update
long statstime = 0;       // Time when we move the stats to history 
char filename[MAXLINE];   // A string to hold filenames
struct timespec last_entry;

// Serialize access to statistics
pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;

// Types of statistics. If this changes, update the entire section 
enum period{cur, hist};
enum type{n, avg, ss};
enum dim{vol, sym};
double stats[2][3][2][BRICK_DIMENSION]; // historical and current stats for attack detection

// Parameters from as.config
map<string,double> parms;

/* Variables for DB access
sql::Driver *driver;
sql::Connection *con;
sql::PreparedStatement *stmt;
sql::ResultSet *res;
*/

// Keeping track of procesed flows
long int processedflows = 0;
long int processedbytes = 0;
int nl = 0;
int l = 0;
int mal = 0;
int inserts = 0;
int cinserts = 0;

// Trim strings 
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

// Parse configuration file and load into parms
void
parse_config (map <string,double>& parms)
{
  char *s, buff[256];
  FILE *fp = fopen ("as.config", "r");
  if (fp == NULL)
  {
    cout <<"Config file as.config does not exist. Please include it and re-run.. \n";
    exit (0);
  }
  cout << "Reading config file as.config ...";
  while ((
	  s = fgets (buff, sizeof buff, fp)) != NULL)
  {
        // Skip blank lines and comment lines 
        if (buff[0] == '\n' || buff[0] == '#')
          continue;

	// Look for = sign and abort if that does not
	// exist
	char name[MAXLINE], value[MAXLINE];
	int found = -1;
	for(int i=0; i<strlen(buff); i++)
	  {
	    if (buff[i] == '=')
	      {
		strncpy(name,buff, i);
		name[i] = 0;
		found = i;
	      }
	    else if((buff[i] == ' ' || buff[i] == '\n') && found >= 0)
	      {
		strncpy(value,buff+found+1,i-found-1);
		value[i-found-1] = 0;
		break;
	      }
	  }
	if (found == -1)
	  continue;
	trim(name);
	trim(value);
	parms.insert(pair<string,double>(name,strtod(value,0)));
  }
  fclose (fp);
}

// Calculate a signature for flows in a samples bin
long calcSignature(long timestamp, int index, int aoci)
{
  int diff = MAX_DIFF;
  long timeinmap = 0;
  long t = timestamp;
  /*
  if (samples.find(timestamp) == samples.end())
    {
      // Find the closest timestamp to attack time
      for (map<long,sample>::iterator it = samples.begin(); it != samples.end(); it++)
	{
	  if (abs(it->first - timestamp) < diff)
	    {
	      timeinmap = it->first;
	      diff = abs(it->first - timestamp);
	    }
	}
      // Didn't find it
      if (timeinmap == 0)
	return 0;
      else
	t = timeinmap;
	}*/
  return t;
}

// Check if the signature contains all zeros
int empty(flow_t sig)
{
  return ((sig.src == 0) && (sig.sport == 0) &&
	  (sig.dst == 0) && (sig.dport == 0) &&
	  (sig.proto == 0));
}


// Add a flow to the samples bin
void addSample(int index, flow_p* f, flow_t* key)
{
  // Create some partial signatures for this flow, like src-dst combination,
  // src-sport, etc
  for (int s=0; s<8; s++)
    {
      flow_t k = *key;
      k.proto = f->flow.proto;
      if ((s & 4) > 0)
	{
	  // Jelena perhaps should deal with protocols
	  if (k.src == 0 && k.dst == f->flow.dst)
	    k.src = f->flow.src;
	  else if (k.src == f->flow.src && k.dst == 0)
	    k.dst = f->flow.dst;
	  // Both are zero, assume dst
	  else
	    k.dst = f->flow.dst;
	}
      if ((s & 2) > 0)
	if (k.sport == 0)
	  k.sport = f->flow.sport;
	else
	  k.src = f->flow.src;
      if ((s & 1) > 0)
	if (k.dport == 0)
	  k.dport = f->flow.dport;
	else
	  k.src = f->flow.src;
      // src, dst, sport, dport
      // Overload len so we can track frequency of contributions
      // Jelena - there was continue here
      // Insert sample if it does not exist
      if (samples.bins[index].flows[s].flow == k)
	{
	  // Else increase contributions of this signature wrt symmetry
	  samples.bins[index].flows[s].len += abs(f->oci);
	  samples.bins[index].flows[s].oci += f->oci;
	}
      else
	{
	  // Boyer Moore to find signatures that cover the most flows
	  if (empty(samples.bins[index].flows[s].flow))
	    samples.bins[index].flows[s].flow = k;
	  else
	    {
	      samples.bins[index].flows[s].len -= abs(f->oci);
	      // Replace this signature if there's another one,
	      // which covers more
	      if (samples.bins[index].flows[s].len < 0)
		{
		  samples.bins[index].flows[s].flow = k;
		  samples.bins[index].flows[s].len = abs(f->oci);
		  samples.bins[index].flows[s].oci = f->oci;
		}
	    }
	}
    }	
} 


// Does this flow match the given signature
int match(flow_t flow, flow_t sig)
{
  if (flow.proto != sig.proto && sig.proto != 0)
    return 0;
  if (empty(sig))
    return 0;
  if ((flow.src == sig.src || sig.src == 0) &&
      (flow.sport == sig.sport || sig.sport == 0) &&
      (flow.dst == sig.dst || sig.dst == 0) &&
      (flow.dport == sig.dport || sig.dport == 0))
    return 1;
  else
    return 0;
}

// Is this timestamp within the range, which we expect in a given input file
int malformed(long timestamp)
{
  if (timestamp < firsttimeinfile || timestamp > firsttimeinfile +
      parms["file_interval"])
    return 1;
  return 0;
}


void rememberFlow(flow_t flow, int len, long start, long end, int oci)
{
  for (long i = start; i <= end; i+= parms["interval"])
    {
      // Too late for this flow
      if (i < freshtime)
	{
	  continue;
	}
      
      // New timestamp, insert into structure
      map<long,time_flow*>::iterator it = timeflows.find(i);
      if (it == timeflows.end())
	{
	  time_flow* tf = new time_flow();
	  tf->fresh = 0;
	  timeflows.insert(pair<long,time_flow*>(i,tf));
	  inserts++;
	  it = timeflows.find(i);
	}
      // Add the flow and remember that this is a fresh record for this
      // processing interval
      flow_p f={start, end, len, oci, flow};
      it->second->flows.push_back(f);
      it->second->fresh++; 
    }
}

void
addSamples(int s_bucket, int d_bucket, flow_p* fp, cell* c, flow_t* key)
{
  // If we've not yet signaled an attack but the flow's oci is of the
  // same sign as the stats for its bin, collect this flow in samples
  // for possible signature later
  int bucket = s_bucket;
  for (int i=0; i<2; i++)
    {
      if (bucket == -1)
	{
	  if (bucket == s_bucket)
	    {
	      bucket = d_bucket;
	      continue;
	    }
	  else
	    return;
	}

      if (!is_attack[bucket] && training_done && fp->oci != 0                                                                    	  && sgn(fp->oci) == sgn(c->databrick_s[bucket]))                                                                         	{
	addSample(bucket, fp, key);
      }
      if (bucket == s_bucket)
	bucket = d_bucket;
    }
}

// Main function, which processes each flow
void
amonProcessing(flow_t flow, int len, long start, long end, int oci)
{
  // Detect if the flow is malformed and reject it
  if (malformed(start) || malformed(end))
    {
      mal++;
      return;
    }
  // Standardize time
  curtime = start;
  start = int(int(start / parms["interval"])*parms["interval"]);
  end = int(int(end / parms["interval"])*parms["interval"]);

  flow_p fp={start, end, len, oci, flow};
      
  int d_bucket = -1, s_bucket = -1;	    // indices for the databrick 

  cell *c = &cells[crear];
  
  for (int way = FOR; way < CLI; way++) // SERV is included in CLI
    {
      flow_t key = {0, 0, 0, 0, 0};
      // Find buckets on which to work
      if (way == FOR)
	{
	  if (flow.dlocal)
	    {
	      s_bucket = myhash(flow.src, 0, FOR);
	      c->databrick_p[s_bucket] += len;
	      c->databrick_s[s_bucket] += oci;
	      key.src = flow.src;
	    }
	  if (flow.slocal)
	    {
	      d_bucket = myhash(flow.dst, 0, FOR);
	      c->databrick_s[d_bucket] += oci;
	      key.dst = flow.dst;
	    }
	}
      else if (way == LOC || way == LOCPREF)
	{
	  if (flow.dlocal)
	    {
	      d_bucket = myhash(flow.dst, 0, way);
	      c->databrick_p[d_bucket] += len;
	      c->databrick_s[d_bucket] += oci;
	      key.dst = flow.dst;
	    }
	  if (flow.slocal)
	    {
	      s_bucket = myhash(flow.src, 0, way);
	      c->databrick_s[s_bucket] += oci;
	      key.src = flow.src;
	    }	      
	}
      else if (way == SERV) // CLI is included in SERV
	{
	  if (flow.dlocal)
	    {
	      if (isservice(flow.dport))
		{
		  d_bucket = myhash(0, flow.dport, SERV);
		  key.dport = flow.dport;
		}
	      else if (isservice(flow.sport))
		{
		  d_bucket = myhash(0, flow.sport, CLI);
		  key.sport = flow.sport;
		}
	      else
		{
		  d_bucket = myhash(0, 0, CLI);
		}
	    }
	  if (flow.slocal)
	    {
	      if (isservice(flow.sport))
		{
		  s_bucket = myhash(0, flow.sport, SERV);
		  key.sport = flow.sport;
		}
	      else if (isservice(flow.dport))
		{
		  s_bucket = myhash(0, flow.dport, CLI);
		  key.dport = flow.dport;
		}
	      else
		{
		  s_bucket = myhash(0, 0, CLI);
		}
	    }
	  c->databrick_p[d_bucket] += len;
	  c->databrick_s[d_bucket] += oci;
	  c->databrick_s[s_bucket] += oci;	 
	}
      addSamples(s_bucket, d_bucket, &fp, c, &key);
    }
}

// Function to detect values higher than mean + parms[numstd] * stdev 
int abnormal(int type, int index, cell* c)
{
  // Look up std and mean
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/
		    (stats[hist][n][type][index]-1));
  // Look up current value
  int data;
  if (type == vol)
    data = c->databrick_p[index];
  else
    data = c->databrick_s[index];
  // Volume larger than mean + numstd*stdev is abnormal 
  if (type == vol && data > mean + parms["numstd"]*std)
    {
      return 1;
    }
  // Symmetry larger than mean + numstd*stdev or
  // smaller than mean - numstd*stdev is abnormal 
  else if (type == sym && ((data > mean + parms["numstd"]*std) ||
			   (data < mean - parms["numstd"]*std)))
    {
      return 1;
    }
  else
    {
      return 0;
    }
}

// Update statistics
void update_stats(cell* c)
{
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      for (int j=vol; j<=sym; j++)
	{
	  int data;
	  if (j == vol)
	    data = c->databrick_p[i];
	  else
	    data = c->databrick_s[i];
	  // Only update if everything looks normal 
	  if (!is_abnormal[i])
	    {
	      // Update avg and ss incrementally
	      stats[cur][n][j][i] += 1;
	      if (stats[cur][n][j][i] == 1)
		{
		  stats[cur][avg][j][i] =  data;
		  stats[cur][ss][j][i] =  0;
		}
	      else
		{
		  int ao = stats[cur][avg][j][i];
		  stats[cur][avg][j][i] = stats[cur][avg][j][i] +
		    (data - stats[cur][avg][j][i])/stats[cur][n][j][i];
		  stats[cur][ss][j][i] = stats[cur][ss][j][i] +
		    (data-ao)*(data - stats[cur][avg][j][i]);
		}
	    }
	}
    }
  trained++;
  if (trained == parms["min_train"])
    {
      cout<<"Current becomes historical "<<endl;
      if (!training_done)
	{
	  training_done = true;
	  cout<<"Training has completed\n";
	}
      trained = 0;
     
      for (int x = ss; x >= n; x--)
	for (int j = vol; j <= sym; j++)
	  for(int i = 0; i<BRICK_DIMENSION; i++)
	  {
	    // Check if we have enough samples.
	    // If the attack was long maybe we don't
	    if (stats[cur][n][j][i] <
		parms["min_train"]*MIN_SAMPLES)
		continue;
	    stats[hist][x][j][i] = stats[cur][x][j][i];
	    stats[cur][x][j][i] = 0;
	  }
    }
}

void findBestSignature(int i, cell* c)
{
  flow_t bestsig = {0,0,0,0,0};
  int oci = 0;
  int maxoci = 0;
  int totoci = c->databrick_s[i];
  
  // Go through candidate signatures
  for (int s=0; s<8; s++)
    {
      if (empty(samples.bins[i].flows[s].flow))
	continue;
      // Print out each signature for debugging
      if (verbose)
	cout<<"SIG: "<<i<<" candidate "<<printsignature(samples.bins[i].flows[s].flow)<<" v="<<samples.bins[i].flows[s].len<<" o="<<samples.bins[i].flows[s].oci<<" toto="<<totoci<<endl;
      // This signature covers more than the maximum, remember
      // this new maximum
      if (abs(samples.bins[i].flows[s].oci) > abs(maxoci))
	maxoci = samples.bins[i].flows[s].oci;
      // Is it a more specific signature with also much
      // more coverage
      if (abs(samples.bins[i].flows[s].oci) > HMB*abs(oci) ||
	  (HMB*abs(samples.bins[i].flows[s].oci) > abs(maxoci) && bettersig(samples.bins[i].flows[s].flow, bestsig)))
	{
	  bestsig = samples.bins[i].flows[s].flow;
	  oci = samples.bins[i].flows[s].oci;
	}
    } 
  if (verbose)
    cout<<"SIG: "<<i<<" best sig "<<printsignature(bestsig)<<" Empty? "<<empty(bestsig)<<" oci "<<maxoci<<" out of "<<totoci<<endl;
  
  // Remember the signature if it is not empty and can filter
  // at least FILTER_THRESH flows in the sample
  if (!empty(bestsig) && (float)oci/totoci > FILTER_THRESH)
    {
      map <flow_t, int> m1, m2;
      // Insert the signature into the array for that bin
      if (signatures.find(i) == signatures.end())
	{
	  stat_f sf = {0, c->databrick_p[i], c->databrick_s[i], bestsig,m1,m2, 0};
	  //signatures.insert(pair<int, stat_f>(i,sf));  // Jelena fix
	}
      else
	{
	  // or replace the signature already there
	  // and reset all the stats
	  signatures[i].sig = bestsig;
	  signatures[i].nflows = 0;
	  signatures[i].matchedflows.clear();
	  signatures[i].reverseflows.clear();
	  signatures[i].timestamp = 0;
	  signatures[i].vol = c->databrick_p[i];
	  signatures[i].oci = c->databrick_s[i];
	}
      // Write the start of the attack into alerts
      ofstream out;
      out.open("alerts.txt", std::ios_base::app);
      out<<i/BRICK_UNIT<<" "<<curtime<<" ";
      out<<"START "<<i<<" "<< c->databrick_p[i];
      out<<" "<<c->databrick_s[i]<<" ";
      out<<printsignature(bestsig)<<endl;
      out.close();
    }
  // Did not find a good signature
  // drop the attack signal and try again later
  else
    {
      if (verbose)
	cout << "AT: Did not find good signature for attack "<<
	  " on bin "<<i<<" best sig "<<empty(bestsig)<<
	  " coverage "<<(float)oci/totoci<<" thresh "<<
	  FILTER_THRESH<<endl;
      is_attack[i] = 0;
    }
}

// This function detects an attack
void detect_attack(cell* c)
{
  // For each bin
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      // Pull average and stdev for volume and symmetry
      double avgv = stats[hist][avg][vol][i];
      double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
      double avgs = stats[hist][avg][sym][i];
      double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));

      /*
      // Attack is going on, it was reported and the bin is still abnormal
      if (is_attack[i] > 0 && is_abnormal[i] > 0 && reported[i] > 1)
	{
	  // How effective is filtering?
	  if (cells[timestamp].databrick_s[i] != 0)
	    {
	      // If they are different sign, just assume everything is filtered
	      double r = (double)cells[timestamp].wfilter_s[i]/cells[timestamp].databrick_s[i];
	      if (r < 0)
		{
		  effective[i] = effective[i]*ALPHA + (1-ALPHA);
		  cout<<"diff sign "<<r<<" filtering is "<<effective[i]<<" effective for bin "<<i<<" w filter "<<cells[timestamp].wfilter_s[i]<<" total "<<cells[timestamp].databrick_s[i]<<endl;
		}
	      else
		{
		  effective[i] = effective[i]*ALPHA+r*(1-ALPHA);
		  cout<<"same sign "<<r<<" filtering is "<<effective[i]<<" effective for bin "<<i<<" w filter "<<cells[timestamp].wfilter_s[i]<<" total "<<cells[timestamp].databrick_s[i]<<endl;
		}
	    }
	  if (verbose)
	    cout<<"Filtering is "<<effective[i]<<" effective for bin "<<i<<" w filter "<<cells[timestamp].wfilter_s[i]<<" total "<<cells[timestamp].databrick_s[i]<<endl;
	  if (effective[i] < EFF_THRESH)
	    {
	      // Signal end of attack. There is anomaly but the signature we have is not
	      // effective anymore
	      if (verbose)
		cout <<"AT: Attack has stopped in destination bin "<< i
		     << " time " << timestamp <<" sig "
		     <<printsignature(signatures[i].sig)<<endl;
	      // Write the end of the attack into alerts
	      ofstream out;
	      out.open("alerts.txt", std::ios_base::app);
	      out << "STOP "<<i<<" "<<timestamp<<endl;
	      out.close();

	      // Write it into DB
	      stmt = con->prepareStatement ("UPDATE attacks SET stop=? WHERE bin=? and stop IS NULL");
	  
	      stmt->setUInt(1, timestamp);
	      stmt->setInt(2, i);
	      stmt->executeUpdate();
	      cout<<"Updated DB set stop="<<timestamp<<" for attack on bin "<<i<<endl;
			
	      delete stmt;
	      
	      // Delete signature if exists
	      if (signatures.find(i) != signatures.end())
		signatures.erase(i);
	      // Reset attack and reported signals
	      is_attack[i] = 0;
	      if (reported[i])
		isfiltered--;
	      reported[i] = 0;
	      effective[i] = 0;
	    }	  
	}
      // How many intervals have elapsed since the attack was reported
      if (reported[i])
	reported[i]++;
      */
      // If both volume and asymmetry are abnormal and training has completed

      int a = abnormal(vol, i, c);
      int b = abnormal(sym, i, c);
      int volume = c->databrick_p[i];
      int asym = c->databrick_s[i];
      if (training_done && abnormal(vol, i, c) && abnormal(sym, i, c))
	{
	  if (verbose)
	    cout<<" abnormal for "<<i<<" points "<<is_abnormal[i]<<" oci "<<c->databrick_s[i]<<" ranges " <<avgs<<"+-"<<stds<<", vol "<<c->databrick_p[i]<<" ranges " <<avgv<<"+-"<<stdv<<endl;
	  
	  // Increase abnormal score, but cap at attack_high/interval
	  if (is_abnormal[i] < int(parms["attack_high"]/parms["interval"]))
	      is_abnormal[i]++;

	  // If abnormal score is above attack_low/interval
	  if (is_abnormal[i] >= int(parms["attack_low"]/parms["interval"])
	      && (is_attack[i] == 0))
	    {
	      // Signal attack detection 
	      is_attack[i] = 1;
	      if (reported[i])
		isfiltered--;
	      reported[i] = 0;
	      effective[i] = 0;
	      if (verbose)
		cout<<"AT: Attack detected on "<<i<<" but not reported yet "<<endl;
	     
	      // Find the best signature
	      findBestSignature(i, c);
	    }
	}
      // Training is completed and both volume and symmetry are normal
      else if (training_done && !abnormal(vol, i, c) && !abnormal(sym, i, c))
	{
	  // Reduce abnormal score
	  if (is_abnormal[i] > 0)
	    {
	      is_abnormal[i] --;
	    }
	  if (is_attack[i] > 0 && is_abnormal[i] == 0)
	    {
	      // Signal end of attack 
	      if (reported[i] > 0)
		{
		  if (verbose)
		    cout <<"AT: Attack has stopped in destination bin "<< i
			 <<" sig "
			 <<printsignature(signatures[i].sig)<<endl;
		  // Write the end of the attack into alerts
		  ofstream out;
		  out.open("alerts.txt", std::ios_base::app);
		  out << "STOP "<<i<<endl;
		  out.close();
		}
	      // Delete signature if exists
	      if (signatures.find(i) != signatures.end())
		signatures.erase(i);
	      // Reset attack and reported signals
	      is_attack[i] = 0;
	      isfiltered--;
	      reported[i] = 0;
	      effective[i] = 0;
	    }
	}
    }
}

void checkReport(int bucket)
{
  if (signatures[bucket].nflows >= SIG_FLOWS)
    {
      int good = 0, bad = 0;
      
      for(map <flow_t, int>::iterator mit = signatures[bucket].matchedflows.begin(); mit != signatures[bucket].matchedflows.end(); mit++)
	{
	  // Symmetry makes a flow good only if it is UDP or TCP+PSH
	  if ((signatures[bucket].reverseflows.find(mit->first) != signatures[bucket].reverseflows.end() &&
	       mit->first.proto == UDP)
	      || (mit->first.proto == TCP && mit->second == 0))
	    {
	      good += signatures[bucket].reverseflows[mit->first];
	      int d = mit->second - signatures[bucket].reverseflows[mit->first];
	      if (d < 0)
		d = 0;
	      bad += d;
	    }
	  else
	    bad += mit->second;
	}
      if (verbose)
	cout<<"SIG: "<<bucket<<" good "<<good<<" bad "<<bad<<" sig "<<printsignature(signatures[bucket].sig)<<endl;
      if ((float)good/(good+bad) <= parms["spec_thresh"])
	{
	  long t = signatures[bucket].timestamp;
	  float rate = (float)signatures[bucket].vol*8/1024/1024/1024;
	  
	  // Dump alert into a file
	  ofstream out;
	  out.open("alerts.txt", std::ios_base::app);
	  out<<bucket/BRICK_UNIT<<" ";
	  out<<"START "<<bucket<<" "<<t<<" "<<rate;
	  out<<" "<<signatures[bucket].oci<<" ";
	  out<<good<<" "<<bad;
	  out<<" "<<printsignature(signatures[bucket].sig)<<endl;
	  out.close();
			  
	  // Insert it DB here
	  /* stmt = con->prepareStatement ("INSERT INTO attacks VALUES (?, NULL, ?, ?)");
	     
			      stmt->setUInt(1, t);
			      stmt->setInt(2, bucket);
			      stmt->setString(3, printsignature(signatures[bucket].sig));
			      stmt->executeUpdate(); 
			      
			      delete stmt;
	  */
	  // Flip the reported bit
	  cout<<"AT: attack on "<<bucket<<" reported at "<<t<<" signature is "<<printsignature(signatures[bucket].sig)<<endl;
	  reported[bucket] = 1;
	  isfiltered++;
	}
      else
	{
	  // Try again Mr Noodle, this was not a good signature
	  if (verbose)
	    cout<<"SIG: attack on "<<bucket<<" signature was not specific enough "<<endl;
	  is_attack[bucket] = 0;
	  signatures.erase(bucket);
	}      
    }
}
  
void matchFlows(int bucket, vector<flow_p>::iterator fit)
{
  if (is_attack[bucket] && reported[bucket] == 0)
    {
      flow_t rflow = {fit->flow.dst, fit->flow.dport,
		      fit->flow.src, fit->flow.sport, fit->flow.proto};
      
      if (match(rflow, signatures[bucket].sig))
	{
	  if (signatures[bucket].reverseflows.find(rflow) ==
	      signatures[bucket].reverseflows.end())
	    {
	      signatures[bucket].reverseflows.insert(pair<flow_t, int>(rflow,0));
	    }
	  if (fit->oci == 0)
	    signatures[bucket].reverseflows[rflow] ++;
	  else
	    signatures[bucket].reverseflows[rflow] += abs(fit->oci);
	}
      // Now deal with exact flow matching
      if (match(fit->flow, signatures[bucket].sig))
	{
	  if (fit->flow.proto == TCP && fit->oci == 0)
	    signatures[bucket].nflows++;
	  else
	    signatures[bucket].nflows+= abs(fit->oci);
	  
	  
	  if (signatures[bucket].matchedflows.find(fit->flow)
	      == signatures[bucket].matchedflows.end())
	    {
	      signatures[bucket].matchedflows.insert(pair<flow_t, int>(fit->flow,0));
	    }
	  if (fit->oci == 0)
	    signatures[bucket].matchedflows[fit->flow] ++;
	  else
	    signatures[bucket].matchedflows[fit->flow] += abs(fit->oci);
	  // Decide if this is really an attack worth reporting, i.e., 
	  // its signature will filter out asymmetric flows but not too 
	  // many symmetric ones
	  checkReport(bucket);
	}
    }      
}

void collectStats(int bucket, vector<flow_p>::iterator fit, map<long,cell*>::iterator it)
{
  if (reported[bucket] > 0)
    {
      if (match(fit->flow, signatures[bucket].sig))
	{
	  // How much volume and asymm. are we filtering
	  it->second->wfilter_p[bucket] += fit->len;	
	  it->second->wfilter_s[bucket] += fit->oci;	
	}
    }
}

// Go through flows for a given timestamp and collect statistics
/*
void processFlows(long timestamp, long starttime)
{
  long difft = time(0) - starttime + 1;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);  
  double telapsed = (double)((now.tv_sec-last_entry.tv_sec)*BILLION+now.tv_nsec-last_entry.tv_nsec)/BILLION;
  clock_gettime(CLOCK_MONOTONIC, &last_entry);  

  long diffs = timestamp - firsttime;
  cout<<"Processed "<<diffs<<" in real time "<<difft<<" processing flows, "<<processedflows/telapsed<<" and GBs "<<int(processedbytes/10000000/difft)/100.0<<" elapsed time "<<telapsed<<" timeflows "<<timeflows.size()<<" cells "<<cells.size()<<" signatures "<<signatures.size()<<" times "<<times.size()<<" inserts "<<inserts<<" cinserts "<<cinserts<<endl;
  inserts = 0;
  cinserts = 0;
  processedflows = 0;

  if (training_done) 
    times.push_back(timestamp);

  int d_bucket = -1, s_bucket = -1;	    // indices for the databrick 

  // Create an empty cell
  cell* c = new cell();
  memset(c->databrick_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c->databrick_s, 0, BRICK_DIMENSION*sizeof(int));
  memset(c->wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c->wfilter_s, 0, BRICK_DIMENSION*sizeof(int));	  
  // Serialize access to stats
  pthread_mutex_lock (&cells_lock);

  // Go through each flow
  map<long,cell*>::iterator it = cells.find(timestamp);

  for (vector<flow_p>::iterator fit=timeflows[timestamp]->flows.begin();  fit != timeflows[timestamp]->flows.end(); fit++)
    {
      // Insert a bin if it does not exist
      if (it == cells.end())
	{
	  cells.insert(pair<long,cell*>(timestamp,c));
	  cinserts++;
	  it = cells.find(timestamp);
	}      
      for (int way = FOR; way < CLI; way++) // SERV is included in CLI
	{
	  // Find buckets on which to work
	  if (way == FOR)
	    {
	      if (fit->flow.dlocal)
		{
		  s_bucket = myhash(fit->flow.src, 0, FOR);
		  it->second->databrick_p[s_bucket] += fit->len;
		  it->second->databrick_s[s_bucket] += fit->oci;
		}
	      if (fit->flow.slocal)
		{
		  d_bucket = myhash(fit->flow.dst, 0, FOR);
		  it->second->databrick_s[d_bucket] += fit->oci;
		}
	    }
	  else if (way == LOC || way == LOCPREF)
	    {
	      if (fit->flow.dlocal)
		{
		  d_bucket = myhash(fit->flow.dst, 0, way);
		  it->second->databrick_p[d_bucket] += fit->len;
		  it->second->databrick_s[d_bucket] += fit->oci;
		}
	      if (fit->flow.slocal)
		{
		  s_bucket = myhash(fit->flow.src, 0, way);
		  it->second->databrick_s[s_bucket] += fit->oci;
		}	      
	    }
	  else if (way == SERV) // CLI is included in SERV
	    {
	      if (fit->flow.dlocal)
		{
		  if (isservice(fit->flow.dport))
		    {
		      d_bucket = myhash(0, fit->flow.dport, SERV);
		    }
		  else if (isservice(fit->flow.sport))
		    {
		      d_bucket = myhash(0, fit->flow.sport, CLI);
		    }
		  else
		    {
		      d_bucket = myhash(0, 0, CLI);
		    }
		}
	      if (fit->flow.slocal)
		{
		  if (isservice(fit->flow.sport))
		    {
		      s_bucket = myhash(0, fit->flow.sport, SERV);
		    }
		  else if (isservice(fit->flow.dport))
		    {
		      s_bucket = myhash(0, fit->flow.dport, CLI);
		    }
		  else
		    {
		      s_bucket = myhash(0, 0, CLI);
		    }
		}
	      it->second->databrick_p[d_bucket] += fit->len;
	      it->second->databrick_s[d_bucket] += fit->oci;
	      it->second->databrick_s[s_bucket] += fit->oci;
	 
	   } 
	  // If we did not report this attack, collect some flows
	  // that match a signature for the attack to see if we would
	  // have too many false positives
	  // First deal with reverse flow matching

	  int bucket = s_bucket;
	  int pass = 0;
	  while(1)
	    {
	      if (bucket == -1)
		{
		  if (pass == 0)
		    {
		      bucket = d_bucket;
		      continue;
		    }
		  else
		    {
		      break;
		    }
		}
	      matchFlows(bucket, fit);	    
	    
	      // If this is a reported attack and we're verbose, let's collect
	      // some statistics on how much we're helping
	      collectStats(bucket, fit, it);
	  
	      // If we've not yet signaled an attack but the flow's oci is of the
	      // same sign as the stats for its bin, collect this flow in samples
	      // for possible signature later
	      if (!is_attack[bucket] && training_done && fit->oci != 0
		  && sgn(fit->oci) == sgn(it->second->databrick_s[bucket]))
		{
		  flow_p f=*fit;
		  addSample(bucket, f, timestamp, way);
		}
	      if (pass == 0)
		bucket = d_bucket;
	      else
		break;
	      pass++;
	    }
	}
    }  
  // Release the lock 
  pthread_mutex_unlock (&cells_lock);

  // Figure out if we've completed the training
  int diff = timestamp - firsttime;

  if(diff > parms["min_train"] && !training_done)
    {
      cout<<"Training has completed"<<endl;
      training_done = 0; // Jelena 1;
      statstime = timestamp;
    }

  // If we did not, let's do the learning
  if (!training_done)
    {
      // If verbose, output debugging statistics into DB
      for (int i=0;i<BRICK_DIMENSION;i++)
	{
	  for (int j=vol; j<=sym; j++)
	    {
	      int data;
	      if (j == vol)
		data = it->second->databrick_p[i];
	      else
		data = it->second->databrick_s[i];

	      // Update avg and ss incrementally
	      stats[hist][n][j][i] += 1;
	      if (stats[hist][n][j][i] == 1)
		{
		  stats[hist][avg][j][i] =  data;
		  stats[hist][ss][j][i] =  0;
		}
	      else
		{
		  int ao = stats[hist][avg][j][i];
		  stats[hist][avg][j][i] = stats[hist][avg][j][i]
		    + (data - stats[hist][avg][j][i])/stats[hist][n][j][i];
		  stats[hist][ss][j][i] = stats[hist][ss][j][i]
		    + (data-ao)*(data - stats[hist][avg][j][i]);
		}
	    }
	}
      // Erase the current statistics
      cells.erase(it);
    }
  else
    {
      // update stats and detect attack
      detect_attack(it->first);
      // do delayed update since it may be that we detect
      // attack a bit later, but the abnormal score starts climbing
      // sooner
      while (times.size() > int(parms["attack_low"]/parms["interval"]))
	{
	  update_stats(times[0]);
	  delete(cells[times[0]]);
	  cells.erase(times[0]);
	  times.erase(times.begin());
	}
    }
  // Erase samples if any
  if (sfront != srear)
    {
      sfront = (sfront + 1) % QSIZE;
    }
}
*/

// Read nfdump flow format
void
amonProcessingNfdump (char* line, long time)
{
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  // Get start and end time of a flow
  char* tokene;
  char saveline[MAXLINE];
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

  // JMM: 100 s up to here
  // Get source and destination IP and port and protocol 
  flow_t flow = {0,0,0,0,0,0};
  int proto = atoi(line+delimiters[4]);
  flow.src = strtol(line+delimiters[8], &tokene, 10);
  flow.sport = atoi(line+delimiters[9]); 
  flow.dst = strtol(line+delimiters[13], &tokene, 10);
  flow.dport = atoi(line+delimiters[14]); 
  flow.proto = proto;
  // JMM 100 s up to here
  flow.slocal = islocal(flow.src);
  flow.dlocal = islocal(flow.dst);
  bytes = atoi(line+delimiters[22]);
  processedbytes+=bytes;
  // JMM: 115 s up to here

  // Cross-traffic, do nothing
  if (!flow.slocal && !flow.dlocal)
    {
      nl++;
      return;
    }
  l++;
  int flags = atoi(line+delimiters[19]);
  pkts = atoi(line+delimiters[21]);
  pkts = (int)(pkts/(dur+1))+1;
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
      // Is this a request or a reply?
      if (isservice(flow.sport) && !isservice(flow.dport))
	oci = -1*pkts;
      // request
      else if (isservice(flow.dport) && !isservice(flow.sport))
	oci = 1*pkts;
      // unknown combination, do nothing
      else
	oci = 0;
    }
  else
    // unknown proto, do nothing
    oci=0;
  
  amonProcessing(flow, bytes, start, end, oci); 
}



// Ever so often go through flows and process what is ready
void *reset_transmit (void* passed_parms)
{
  // Serialize access to cells
  pthread_mutex_lock (&cells_lock);

  // We will process this one now
  int current = cfront;

  // This one will be next for processing
  cfront = (cfront + 1)%QSIZE;
  if (cfront == crear)
    cempty = true;
  
  // Serialize access to cells
  pthread_mutex_unlock (&cells_lock);
  
  cell* c = &cells[current];
  
  // Check if there is an attack that was waiting
  // a long time to be reported. Perhaps we had too specific
  // signature and we will never collect enough matches
  // Serialize access to stats
  update_stats(c);
  if (training_done)
    detect_attack(c);
  cout<<"Done "<<time(0)<<endl;
  // Detect attack here
  pthread_exit (NULL);
}

// Save historical data for later run
void save_history()
{  
  // Only save if training has completed
  if (training_done)
    {
      ofstream out;
      out.open("as.dump", std::ios_base::out);
      for (int i=n; i<=ss;i++)
	for (int j=vol; j<=sym; j++)
	  {
	    out<<i<<" "<<j<<" ";
	    for (int k=0;k<BRICK_DIMENSION;k++)
	      {
		out<<stats[hist][i][j][k]<<" ";
	      }
	    out<<endl;
	  }
      out.close();
    }
}


// Load historical data
void load_history()
{
  ifstream in;
  in.open("as.dump", std::ios_base::in);
  if (in.is_open())
    {
      int malformed = 0;
      for (int i=n; i<=ss;i++)
	for (int j=vol; j<=sym; j++)
	  {
	    int a, b;
	    in>>a>>b;
	    if (a != i || b !=j)
	      {
		malformed = 1;
		break;
	      }
	    for (int k=0;k<BRICK_DIMENSION;k++)
	      {
		in>>stats[hist][i][j][k];
	      }
	  }
      in.close();
      if (!malformed)
	{
	  training_done = true;
	  cout<<"Training data loaded"<<endl;
	}
    }  
}

// Print help for the program
void
printHelp (void)
{
  printf ("amon-senss\n(C) 2018 University of Southern California.\n\n");
  printf ("-h                             Print this help\n");
  printf ("-r <inputfile or inputfolder>  Input is in nfdump or flow-tools file(s)\n");
  printf ("-l                             Load historical data from as.dump\n");
  printf ("-s                             Start from this given file in the input folder\n");
  printf ("-e                             End with this given file in the input folder\n");
  printf ("-v                             Verbose\n");
}


// Main program
int main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  // Parse configuration
  parse_config (parms);
  // Load service port numbers
  numservices = loadservices("services.txt");
  cout<<"Services "<<numservices<<endl;
  loadprefixes("localprefs.txt");
  cout<<"Num prefs "<<numprefs<<endl;
  
  char c, buf[32];
  char *file_in = NULL;
  char *startfile = NULL, *endfile = NULL;
  
  
  while ((c = getopt (argc, argv, "hvlr:s:e:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'r':
	  file_in = strdup(optarg);
	  break;
	case 'l':
	  load_history();
	  break;
	case 's':
	  startfile = strdup(optarg);
	  cout<<"Start file "<<startfile<<endl;
	  break;
	case 'e':
	  endfile = strdup(optarg);
	  cout<<"End file "<<endfile<<endl;
	  break;
	case 'v':
	  verbose = 1;
	  break;
	}
    }
  if (file_in == NULL)
    {
      cerr<<"You must specify an input folder, which holds Netflow records\n";
      exit(-1);
    }
  cout<<"Verbose "<<verbose<<endl;
  /* Connect to DB
  try {
    driver = get_driver_instance();
    con = driver->connect("tcp://127.0.0.1:3306", "amon-senss", "St33llab@isi");
    con->setSchema("AMONSENSS");
   }
  catch (sql::SQLException &e) {
    cerr<<"Could not connect to the DB\n";
  }
  */


  clock_gettime(CLOCK_MONOTONIC, &last_entry);      
  // This is going to be a pointer to input
  // stream, either from nfdump or flow-tools */
  FILE* nf;
  unsigned long long num_pkts = 0;      

  // Read flows from a file
  if (file_in)
    {
      int isdir = 0;
      vector<string> tracefiles;
      vector<string> inputs;
      struct stat s;
      inputs.push_back(file_in);
      int i = 0;
      // Recursively read if there are several directories that hold the files
      while(i < inputs.size())
	{
	  if( stat(inputs[i].c_str(),&s) == 0 )
	    {
	      if(s.st_mode & S_IFDIR )
		{
		  // it's a directory, read it and fill in 
		  // list of files
		  DIR *dir;
		  struct dirent *ent;

		  if ((dir = opendir (inputs[i].c_str())) != NULL) {
		    // Remember all the files and directories within directory 
		    while ((ent = readdir (dir)) != NULL) {
		      if((strcmp(ent->d_name,".") != 0) && (strcmp(ent->d_name,"..") != 0)){
			inputs.push_back(string(inputs[i]) + "/" + string(ent->d_name));
		      }
		    }
		    closedir (dir);
		  } else {
		    perror("Could not read directory ");
		    exit(1);
		  }
		}
	      else if(s.st_mode & S_IFREG)
		{
		  tracefiles.push_back(inputs[i]);
		}
	      // Ignore other file types
	    }
	  i++;
	}
      
      std::sort(tracefiles.begin(), tracefiles.end(), sortbyFilename());

      int started = 1;
      if (startfile != NULL)
	started = 0;
      int allflows = 0;
      double start = time(0);
      // Go through tracefiles and read each one
      for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
      {
	const char* file = vit->c_str();

	if (!started && startfile && strstr(file,startfile) == NULL)
	  {
	    cout<<"No match "<<startfile<<" "<<file<<endl;
	    continue;
	  }

	started = 1;
	
	char cmd[MAXLINE];
	// Try to read as netflow file
	sprintf(cmd,"nfdump -r %s -o pipe 2>/dev/null", file);
	nf = popen(cmd, "r");
	// Close immediately so we get the error code 
	// and we can detect if this is maybe flow-tools format 
	int error = pclose(nf);
	if (error == 64000)
	  {
	    sprintf(cmd,"ft2nfdump -r %s | nfdump -r - -o pipe", file);
	    nf = popen(cmd, "r");
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

	// Now read from file
	char line[MAXLINE];
	cout<<"Reading from "<<file<<endl;
	firsttimeinfile = 0;

	while (fgets(line, MAXLINE, nf) != NULL)
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
	    if (num_pkts == 0)
		firsttime = epoch;
	    num_pkts++;
	    if (firsttimeinfile == 0)
	      firsttimeinfile = epoch;
	    allflows++;
	    if (allflows % 1000000 == 0)
	      {
		double diff = time(0) - start;
		cout<<"Processed "<<allflows<<", 1M in "<<diff<<endl;
		start = time(0);
	      }
	    processedflows++;
	    if (processedflows == MAX_FLOWS)
	      {
		pthread_mutex_lock (&cells_lock);
		// This one we will work on next
		crear = (crear + 1)%QSIZE;
		cout<<"Next cell at "<<crear<<endl;
		if (crear == cfront && !cempty)
		  {
		    perror("QSIZE is too small\n");
		    exit(1);
		  }
		// zero out stats
		cell* c = &cells[crear];
		memset(c->databrick_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
		memset(c->databrick_s, 0, BRICK_DIMENSION*sizeof(int));
		memset(c->wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
		memset(c->wfilter_s, 0, BRICK_DIMENSION*sizeof(int));	  
		// and it will soon be full
		cempty = false;
		pthread_mutex_unlock (&cells_lock);
		
		pthread_t thread_id;
		pthread_create (&thread_id, NULL, reset_transmit, NULL); 
		processedflows = 0;
	      }
	    amonProcessingNfdump(line, epoch); 
	  }
	cout<<"Done with the file "<<file<<" time "<<time(0)<<endl;
	pclose(nf);
	if (endfile && strstr(file,endfile) != 0)
	  break;
      }
    }
  save_history();
  return 0;
}
