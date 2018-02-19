/*
#
# Copyright (C) 2016 University of Southern California.
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
#include <pcap.h>
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <cmath>

#include <dirent.h>

#include "utils.h"

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
// Save all flows for a given time slot
map<long, time_flow> timeflows;
// These are the bins where we store stats
map<long,cell> cells;
// Samples of flows for each time slot
map<long,sample> samples;
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

// Did we complete training
int training_done = 0;
// Verbose bit
int verbose = 0;

long firsttime = 0;       // Beginning of trace 
long freshtime = 0;       // Where we last ended when processing data 
long firsttimeinfile = 0; // First time in the current file 
long updatetime = 0;      // Time of last stats update
long statstime = 0;       // Time when we move the stats to history 
char filename[MAXLINE];   // A string to hold filenames

// Serialize access to statistics
pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;

// Types of statistics. If this changes, update the entire section 
enum period{cur, hist};
enum type{n, avg, ss};
enum dim{vol, sym};
double stats[2][3][2][BRICK_DIMENSION]; // historical and current stats for attack detection

map<string,double> parms;



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

// Parse configuration file
void
parse_config (map <string,double>& parms)
{
  char *s, buff[256];
  FILE *fp = fopen ("amon.config", "r");
  if (fp == NULL)
  {
    cout <<"\n Config file amon.config does not exist. Please include it and re-run.. \n";
    exit (0);
  }
  cout << "\n Reading config file amon.config ...";
  while ((s = fgets (buff, sizeof buff, fp)) != NULL)
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
	cout<<"Insert "<<name<<" "<<value<<endl;
	parms.insert(pair<string,double>(name,strtod(value,0)));
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
      // Find the closest timestamp
      for (map<long,sample>::iterator it = samples.begin(); it != samples.end(); it++)
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
  return t;
}


/*****************************************************************/

void addSample(int index, flow_p f, long i)
{
 
  if (samples.find(i) == samples.end())
    {
      sample m;
      samples.insert(pair<long,sample>(i,m));
    }
  // Figure out first if there is a common dst and either src, sport or src:sport combination
  // always include proto
  for (int s=0; s<8; s++)
    {
      // Default signature matches everything
      // zero is a special value, matching everything.
      // Only allow signatures where destination is known.
      flow_t key = {0,0,0,0,0};     
      key.dst = f.flow.dst;
      key.proto = f.flow.proto;
      // src, sport, dport, proto
      if ((s & 4) > 0)
	key.src = f.flow.src;
      if ((s & 2) > 0)
	key.sport = f.flow.sport;
      if ((s & 1) > 0)
	key.dport = f.flow.dport;
      // Overload len so we can track frequency of contributions
      flow_p fkey = {0, 0, abs(f.oci), f.oci, f.flow};
      if (samples[i].bins[index].flows.find(s) == samples[i].bins[index].flows.end())
	{
	  samples[i].bins[index].flows.insert(pair<int, flow_p>(s, fkey));
	}
      else if (samples[i].bins[index].flows[s].flow == key)
	{
	  samples[i].bins[index].flows[s].len += abs(f.oci);
	  samples[i].bins[index].flows[s].oci += f.oci;
	}
      else
	{
	  samples[i].bins[index].flows[s].len -= abs(f.oci);
	  // Replace this flow
	  if (samples[i].bins[index].flows[s].len < 0)
	    {
	      samples[i].bins[index].flows[s].flow = key;
	      samples[i].bins[index].flows[s].len = abs(f.oci);
	      samples[i].bins[index].flows[s].oci = f.oci;
	    }
	}
    }	
} 

int empty(flow_t sig)
{
  return ((sig.src == 0) && (sig.sport == 0) &&
	  (sig.dst == 0) && (sig.dport == 0) &&
	  (sig.proto == 0));
}
	    
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

int malformed(long timestamp)
{
  if (timestamp < firsttimeinfile || timestamp > firsttimeinfile + parms["file_interval"])
    return 1;
  return 0;
}
/*****************************************************************/

void
amonProcessing(flow_t flow, int len, long start, long end, int oci)
{
  unsigned int payload;

  // Detect if the flow is malformed and reject it
  if (malformed(start) || malformed(end))
    return;

  // Just link the flow into the structure and process
  // when it is ready. For flows that last a long time
  // multiply the flow and insert into each time interval
  

  // Standardize time
  start = int(int(start / parms["interval"])*parms["interval"]);
  end = int(int(end / parms["interval"])*parms["interval"]);
  
  int error;
  if ((error = pthread_mutex_lock (&flows_lock)))
    {
      fprintf (stderr,
	       "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
	       error);
      exit (-1);
    }

  for (long i = start; i <= end; i+= parms["interval"])
    {
      if (i < freshtime)
	continue;
      map<long,time_flow>::iterator it = timeflows.find(i);
      if (it == timeflows.end())
	{
	  time_flow tf;
	  tf.fresh = 0;
	  timeflows.insert(pair<long,time_flow>(i,tf));
	  it = timeflows.find(i);
	}

      flow_p f={start, end, len, oci, flow};
      it->second.flows.push_back(f);
      it->second.fresh++;
    }
  if ((error = pthread_mutex_unlock (&flows_lock)))
    {
      fprintf (stderr,
	       "Error Number %d For Releasing Lock. FATAL ERROR. \n",
	       error);
      exit (-1);
    }
}
//=======================================================================//
//===== Function to detect values higher than mean + parms[numstd] * stdev ====//
//=====================================================================//
int abnormal(int type, int index, unsigned int timestamp)
{
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/(stats[hist][n][type][index]-1));
  int data;
  if (type == vol)
    data = cells[timestamp].databrick_p[index];
  else
    data = cells[timestamp].databrick_s[index];

  if (type == vol && data > mean + parms["numstd"]*std)
    return 1;
  else if (type == sym && abs(data) > abs(mean) + parms["numstd"]*abs(std))
    return 1;
  else
    return 0;
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
		//if (!abnormal(j, i, timestamp))
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
	  double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));
	  double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
	}
      updatetime = timestamp;
    }
  if (timestamp - statstime >= parms["min_train"] && training_done)
    {
      cout<<"========================> Updating means "<<timestamp<<" statstime "<<statstime<<endl;
      statstime = timestamp;
      for (int j = n; j <= ss; j++)
	for (int k = vol; k <= sym; k++)
	  {
	    // Move cur arrays into hist and zero down cur
	    memcpy (stats[hist][j][k], stats[cur][j][k], BRICK_DIMENSION * sizeof (double));
	    memset ((double*)stats[cur][j][k], 0, BRICK_DIMENSION * sizeof (double));
	  }
    }
}


void minmax(int* array, int len, int &min, int &max)
{
  min = ~(int)0;
  max = 0;
  for (int i=0; i<len; i++)
    {
      if(array[i] < min)
	min = array[i];
      if(array[i] > max)
	max = array[i];
    }
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

      debug[i]<<timestamp<<" "<<avgv<<" ";
      debug[i]<<stdv<<" "<<cells[timestamp].databrick_p[i]<<" ";
      debug[i]<<avgs<<" "<<stds<<" ";
      debug[i]<<cells[timestamp].databrick_s[i]<<" ";
      debug[i]<<cells[timestamp].wfilter_p[i]<<"  ";
      debug[i]<<cells[timestamp].wfilter_s[i]<<"  ";
      debug[i]<<is_attack[i]<<endl;
      
      if (training_done && abnormal(vol, i, timestamp) && abnormal(sym, i, timestamp))
	{
	  cout<<timestamp<<" abnormal for "<<i<<" points "<<is_abnormal[i]<<" oci "<<cells[timestamp].databrick_s[i]<<" beyond " <<avgs<<"+-"<<stds<<" vol "<<cells[timestamp].databrick_p[i]<<" beyond " <<avgv<<"+-"<<stdv<<" matchedflows "<<signatures[i].matchedflows.size()<<endl;

	  if (is_abnormal[i] < int(parms["attack_high"]/parms["interval"]))
	      is_abnormal[i]++;
	  int v=cells[timestamp].databrick_p[i];
	  int s=cells[timestamp].databrick_s[i];
	  if (is_abnormal[i] >= int(parms["attack_low"]/parms["interval"])
	      && (is_attack[i] == 0))
	    {
	      /* Signal attack detection */
	      is_attack[i] = 1;
	      reported[i] = 0;
	      cout<<"Attack detected on "<<i<<" but not reported yet, timestamp "<<timestamp<<endl;

	      // Find closest timestamp and calculate signatures
	      long t = calcSignature(timestamp, i, s);
	      if (t > 0)
		{
		  cout<<"-----> AT"<<i<<" possible attack at time "<<t<<endl;
		  
		  // Find best signature
		  flow_t bestsig = {0,0,0,0,0};
		  int oci = 0;
		  int maxoci = 0;
		  int totoci = cells[t].databrick_s[i];
		  
		  for (map<int,flow_p>::iterator sit = samples[t].bins[i].flows.begin(); sit != samples[t].bins[i].flows.end(); sit++)
		    {
		      // Print out each signature for debugging
		      cout<<"AT"<<i<<" candidate "<<printsignature(sit->second.flow)<<" v="<<sit->second.len<<" o="<<sit->second.oci<<" toto="<<totoci<<endl;
		      if (abs(samples[t].bins[i].flows[sit->first].oci) > abs(maxoci))
			maxoci = samples[t].bins[i].flows[sit->first].oci;
		      if (abs(samples[t].bins[i].flows[sit->first].oci) > HMB*abs(oci) ||
			  (HMB*abs(samples[t].bins[i].flows[sit->first].oci) > abs(maxoci) && bettersig(sit->second.flow, bestsig)))
			{
			  bestsig = sit->second.flow;
			  oci = sit->second.oci;
			}
		    }
		  cout<<"AT"<<i<<" best sig "<<printsignature(bestsig)<<" Empty? "<<empty(bestsig)<<" oci "<<maxoci<<" out of "<<totoci<<endl;
		  // Remember the signature if it is not empty
		  if (!empty(bestsig) && (float)oci/totoci > parms["filter_thresh"])
		    {
		      map <flow_t, int> m1, m2;
		      if (signatures.find(i) == signatures.end())
			{
			  stat_f sf = {t, cells[t].databrick_p[i], cells[t].databrick_s[i], bestsig,m1,m2, 0};
			  signatures.insert(pair<int, stat_f>(i,sf));
			}
		      else
			{
			  signatures[i].sig = bestsig;
			  signatures[i].nflows = 0;
			  signatures[i].matchedflows.clear();
			  signatures[i].reverseflows.clear();
			  signatures[i].timestamp = t;
			  signatures[i].vol = cells[t].databrick_p[i];
			  signatures[i].oci = cells[t].databrick_s[i];
			}
		      cout<<"AT"<<i<<" inserted sig "<<printsignature(signatures[i].sig)<<endl;
		    }
		  // Did not find a good signature
		  // drop the attack signal and try again later
		  else
		    {
		      cout << "Did not find good signature for attack on bin "<<i<<" best sig "<<empty(bestsig)<<" ration "
			   <<(float)oci/totoci<<" thresh "<<parms["filter_thresh"]<<endl;
		      is_attack[i] = 0;
		    }
		}
	      else
		{
		  cout << "Did not matching signatures for attack on bin "<<i<<endl;
		  is_attack[i] = 0;
		}
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
	      if (reported[i] > 0)
		{
		  cout <<" Attack has stopped in destination bin "<< i << " time " << timestamp <<" sig "<<printsignature(signatures[i].sig)<<endl;
		  ofstream out;
		  out.open("alerts.txt", std::ios_base::app);
		  out << "STOP "<<i<<" "<<timestamp<<endl;
		  out.close();
		  cout<<"AT"<<i<<" erasing signature 1"<<endl;
		  signatures.erase(i);
		}
	      is_attack[i] = 0;
	      reported[i] = 0;
	    }
	}
    }
}

void processFlows(long timestamp)
{
  times.push_back(timestamp);
  int d_bucket = 0, s_bucket = 0;	    /* indices for the databrick */

  cell c;
  memset(c.databrick_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c.databrick_s, 0, BRICK_DIMENSION*sizeof(int));
  memset(c.wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c.wfilter_s, 0, BRICK_DIMENSION*sizeof(int));	  

  int error = 0;
  if ((error = pthread_mutex_lock (&cells_lock)))
    {
      fprintf (stderr,
	       "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
	       error);
      exit (-1);
    }
  cout<<"Process flows for "<<timestamp<<endl;
  map<long,cell>::iterator it = cells.find(timestamp);
  for (vector<flow_p>::iterator fit=timeflows[timestamp].flows.begin();  fit != timeflows[timestamp].flows.end(); fit++)
    {
      // One empty cell
      s_bucket = hash(fit->flow.src); // Jelena: should add  & mask
      d_bucket = hash(fit->flow.dst); // Jelena: should add  & mask 

      if (it == cells.end())
	{
	  cells.insert(pair<long,cell>(timestamp,c));
	  it = cells.find(timestamp);
	}
      it->second.databrick_p[d_bucket] += fit->len;	// add bytes to payload databrick for dst
      it->second.databrick_s[d_bucket] += fit->oci;	// add oci to symmetry databrick for dst
      it->second.databrick_s[s_bucket] -= fit->oci;	// subtract oci from symmetry databrick for src
      it->second.wfilter_p[d_bucket] += fit->len;	// add bytes to payload databrick for dst
      it->second.wfilter_s[d_bucket] += fit->oci;	// add oci to symmetry databrick for dst
      it->second.wfilter_s[s_bucket] -= fit->oci;	// subtract oci from symmetry databrick for src

      if (is_attack[s_bucket] && reported[s_bucket] == 0)
	{
	  flow_t rflow = {fit->flow.dst, fit->flow.dport, fit->flow.src, fit->flow.sport, fit->flow.proto};
	  
	  if (match(rflow, signatures[s_bucket].sig))
	    {
	      //cout<<"RFlow "<<printsignature(rflow)<<" matches "<<printsignature(signatures[s_bucket].sig)<<endl;
	      if (signatures[s_bucket].reverseflows.find(rflow) == signatures[s_bucket].reverseflows.end())
		{
		  signatures[s_bucket].reverseflows.insert(pair<flow_t, int>(rflow,0));
		}
	      if (fit->oci == 0)
		signatures[s_bucket].reverseflows[rflow] ++;
	      else
		signatures[s_bucket].reverseflows[rflow] += abs(fit->oci);
	    }
	}
	
      if (is_attack[d_bucket] && reported[d_bucket] == 0)
	{
	  if (match(fit->flow, signatures[d_bucket].sig))
	    {
	      if (fit->flow.proto == TCP && fit->oci == 0)
		signatures[d_bucket].nflows++;
	      else
		signatures[d_bucket].nflows+= abs(fit->oci);
	      cout<<"AT"<<d_bucket<<" flow "<<printsignature(fit->flow)<<" len "<<fit->len<<" oci "<<fit->oci<<" nflows "<<signatures[d_bucket].nflows<<endl;
	      if (signatures[d_bucket].matchedflows.find(fit->flow) == signatures[d_bucket].matchedflows.end())
		{
		  signatures[d_bucket].matchedflows.insert(pair<flow_t, int>(fit->flow,0));
		}
	      if (fit->oci == 0)
		signatures[d_bucket].matchedflows[fit->flow] ++;
	      else
		signatures[d_bucket].matchedflows[fit->flow] += abs(fit->oci);
	      
	      
	      // Decide if this is really an attack worth reporting, i.e., 
	      // its signature will filter out asymmetric flows but not too 
	      // many symmetric ones 
	      if (signatures[d_bucket].nflows >= parms["sig_flows"])
		{
		  int good = 0, bad = 0;
		  
		  for(map <flow_t, int>::iterator mit = signatures[d_bucket].matchedflows.begin(); mit != signatures[d_bucket].matchedflows.end(); mit++)
		      {
			// Symmetry makes a flow good only if it is UDP or TCP+PSH
			if (signatures[d_bucket].reverseflows.find(mit->first) != signatures[d_bucket].reverseflows.end() &&
			    mit->first.proto == UDP || (mit->first.proto == TCP && mit->second == 0))
			  {
			    good += signatures[d_bucket].reverseflows[mit->first];
			    int d = mit->second - signatures[d_bucket].reverseflows[mit->first];
			    if (d < 0)
			      d = 0;
			    bad += d;
			  }
			else
			  bad += mit->second;
		      }
		    cout<<"AT"<<d_bucket<<" good "<<good<<" bad "<<bad<<" sig "<<printsignature(signatures[d_bucket].sig)<<endl;
		    if ((float)good/(good+bad) < parms["spec_thresh"])
		      {
			long t = signatures[d_bucket].timestamp;
			float rate = (float)signatures[d_bucket].vol*8/1024/1024/1024;
			cout <<"Attack detected in destination bin " << d_bucket << " time " << t <<" vol "<<rate<<" Gbps oci "<<signatures[d_bucket].oci<<" good dropped "<< good<<" bad dropped "<<bad<<endl;
			cout<<"Signature "<<printsignature(signatures[d_bucket].sig)<<endl;
			
			// Dump alert into a file 
			ofstream out;
			out.open("alerts.txt", std::ios_base::app);
			out<<"START "<<d_bucket<<" "<<t<<" "<<rate;
			out<<" "<<signatures[d_bucket].oci<<" ";
			out<<good<<" "<<bad;
			out<<" "<<printsignature(signatures[d_bucket].sig)<<endl;
			out.close();
			reported[d_bucket] = 1;
		      }
		    else
		      {
			// Try again Mr Noodle 
			cout<<"AT"<<d_bucket<<" erasing signature 2"<<endl;					    
			is_attack[d_bucket] = 0;
			signatures.erase(d_bucket);
		      }
		  }
	      }
	}
	if (reported[d_bucket] == 1)
	  {	
	    if (match(fit->flow, signatures[d_bucket].sig))
	      {
		//cout<<"Filtering flow "<<printsignature(flow)<<" for bucket "<<d_bucket<<endl;
		// Undo changes for wfilter 
		it->second.wfilter_p[d_bucket] -= fit->len;	
		it->second.wfilter_s[d_bucket] -= fit->oci;	
		it->second.wfilter_s[s_bucket] += fit->oci;
	      }
	  }
	
	if (!is_attack[d_bucket] && training_done && fit->oci != 0 && sgn(fit->oci) == sgn(it->second.databrick_s[d_bucket]))
	  {
	    flow_p f=*fit;
	    addSample(d_bucket, f, timestamp);
	  }
      
	if ((error = pthread_mutex_unlock (&cells_lock)))
	  {
	    fprintf (stderr,
		     "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		     error);
	    exit (-1);
	  }	
    }
  int diff = timestamp - firsttime;
  if(diff > parms["min_train"] && !training_done)
    {
      training_done = 1;
      statstime = timestamp;
    }
  
  if (!training_done)
    {
      // do learning
      for (int i=0;i<BRICK_DIMENSION;i++)
	{
	  for (int j=vol; j<=sym; j++)
	    {
	      int data;
	      if (j == vol)
		data = it->second.databrick_p[i];
	      else
		data = it->second.databrick_s[i];
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
       cells.erase(it);
    }
  else
    {
      // update stats and detect attack
      detect_attack(it->first);
      // do delayed update since it may be that we detect
      // attack later
      while (times.size() > int(parms["attack_low"]/parms["interval"]))
	{
	  update_dst_arrays(times[0]);
	  cells.erase(times[0]);
	  times.erase(times.begin());
	}
    }
  if (samples.find(it->first) != samples.end())
    {
      cout<<"Erasing "<<it->first<<endl;
      samples.erase(it->first);
    }
  //cells.erase(it);
}


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
      // TODO: Add real service ports
      if ((flow.sport < 1024 || flow.sport == 1900) && flow.dport >= 1024)
	oci = -1*pkts;
      // request
      else if (flow.sport >= 1024 && (flow.dport < 1024 || flow.dport == 1900))
	oci = 1*pkts;
      // unknown, do nothing
      else
	oci = 0;
    }
  else
    // unknown, do nothing
    oci=0;
  
  amonProcessing(flow, bytes, start, end, oci);
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
      cout<<"******"<<endl;
      if ((error = pthread_mutex_lock (&flows_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      // Find timestamps that are not fresh
      for (map<long,time_flow>::iterator it=timeflows.begin(); it != timeflows.end(); )
	{
	  curtime = it->first;
	  int diff = curtime - firsttime;

	  cout<<"Reset "<<it->first<<" "<<it->second.fresh<<" flow "<<it->second.flows.size()<<endl;
	  if (it->second.fresh || fresh)
	    {
	      if (fresh == 0 || (fresh <= MIN_FRESH && it->second.flows.size() >= MIN_FLOWS))
		{
		  fresh = 1;
		  freshtime = curtime;
		  cout<<"Reset "<<training_done<<" freshtime "<<freshtime<<" curtime "<<curtime<<" first "<<firsttime<<" diff "<<diff<<" timeflows "<<timeflows.size()<<" fresh "<<it->second.fresh<<" global fresh "<<fresh<<endl;

		}
	      it->second.fresh = 0;
	      it++;
	      continue;
	    }
	  else
	    {
	      // Process this batch of flows
	      // Do something to collect stats, detect attack, etc
	      processFlows(it->first);
	      timeflows.erase(it++);
	    }
	}
      if ((error = pthread_mutex_unlock (&flows_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      /* Check if there is an attack that was waiting a long time to be reported */      
      if ((error = pthread_mutex_lock (&cells_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Acquiring Lock. FATAL ERROR. \n",
		   error);
	  exit (-1);
	}
      for (map<int,stat_f>::iterator sit = signatures.begin(); sit != signatures.end();)
	{
	  long t = sit->second.timestamp;
	  if (freshtime - t < parms["report_thresh"])
	    {
	      sit++;
	      continue;
	    }
	  if (is_attack[sit->first] && !reported[sit->first])
	    {
	      cout<<"AT"<<sit->first<<" not enough matching flows "<<sit->second.nflows<<endl;
	      is_attack[sit->first] = 0;
	      signatures.erase(sit++);
	    }
	  else
	    sit++;
	}
      if ((error = pthread_mutex_unlock (&cells_lock)))
	{
	  fprintf (stderr,
		   "Error Number %d For Releasing Lock. FATAL ERROR. \n",
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
    ("-r <inputfile>  Input is in nfdump or flow-tools file\n");
  printf ("-f <filter>     [BPF filter]\n");
  printf ("-v              Verbose\n");
}



int
main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  parse_config (parms);
  cout<<"Interval "<<parms["interval"]<<" min train "<<parms["min_train"]<<endl;
  char c, buf[32];
  u_int32_t flags = 0;
  int i = 0;
  pthread_t thread_id;
  int retstatus;
  char *bpfFilter = NULL;
  char *pcap_in = NULL;
  struct bpf_program fcode;
  int ispcap = 0; /* Flag telling us the file format, pcap or nfdump/flow-tools */


  while ((c = getopt (argc, argv, "h:vf:r:")) != '?')
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
	  pcap_in = strdup (optarg);
	  break;
	case 'f':
	  bpfFilter = strdup (optarg);
	  break;
	case 'v':
	  verbose = 1;
	  break;
	}
    }

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
		perror("Could not read directory ");
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
	
	pt = pcap_open_offline (file, ebuf);
	if (pt)
	  ispcap = 1;
	else
	  {
	    ispcap = 0;
	    char cmd[MAXLINE];
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

	  }
	else
	  {
	    cout<<"Filter with nfdump, unsupported\n";
	    /* Filter with nfdump, so far this is unsupported */
	  }
	if (ispcap)
	  {
	  }
	else
	  {
	    char line[MAXLINE];
	    cout<<"Trying to read from "<<nf<<endl;
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
		if (num_pcap_pkts == 0)
		  {
		    firsttime = epoch;
		    beginning.tv_sec = epoch;
		    beginning.tv_usec = msec*1000;
		    printf ("First packet seen at %ld\n",
			    beginning.tv_sec * 1L);
		  }
		num_pcap_pkts++;
		if (firsttimeinfile == 0)
		  firsttimeinfile = epoch;
		amonProcessingNfdump(line, epoch);
	      }
	  }     
	cout<<"------> Done with the file "<<time(0)<<endl;
      }
    }
  return 0;			// Exit program
}
