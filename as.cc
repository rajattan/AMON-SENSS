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

// Parameters from as.config
map<string,double> parms;

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
    }
  return t;
}


// Add a flow to the samples bin
void addSample(int index, flow_p f, long i)
{
  // Insert the bin if it does not exist
  if (samples.find(i) == samples.end())
    {
      sample m;
      samples.insert(pair<long,sample>(i,m));
    }
  // Create some partial signatures for this flow, like src-dst combination,
  // src-sport, etc
  for (int s=0; s<8; s++)
    {
      // Default signature matches everything
      // Only allow signatures with defined proto and dst ip
      flow_t key = {0,0,0,0,0};     
      key.proto = f.flow.proto;
      key.dst = f.flow.dst;
      // src, sport, dport
      if ((s & 4) > 0)
	key.src = f.flow.src;
      if ((s & 2) > 0)
	key.sport = f.flow.sport;
      if ((s & 1) > 0)
	key.dport = f.flow.dport;
      // Overload len so we can track frequency of contributions
      flow_p fkey = {0, 0, abs(f.oci), f.oci, f.flow};
      // Insert sample if it does not exist
      if (samples[i].bins[index].flows.find(s) ==
	  samples[i].bins[index].flows.end())
	{
	  samples[i].bins[index].flows.insert(pair<int, flow_p>(s, fkey));
	}
      else if (samples[i].bins[index].flows[s].flow == key)
	{
	  // Else increase contributions of this signature wrt symmetry
	  samples[i].bins[index].flows[s].len += abs(f.oci);
	  samples[i].bins[index].flows[s].oci += f.oci;
	}
      else
	{
	  // Boyer Moore to find signatures that cover the most flows
	  samples[i].bins[index].flows[s].len -= abs(f.oci);
	  // Replace this signature if there's another one,
	  // which covers more
	  if (samples[i].bins[index].flows[s].len < 0)
	    {
	      samples[i].bins[index].flows[s].flow = key;
	      samples[i].bins[index].flows[s].len = abs(f.oci);
	      samples[i].bins[index].flows[s].oci = f.oci;
	    }
	}
    }	
} 

// Check if the signature contains all zeros
int empty(flow_t sig)
{
  return ((sig.src == 0) && (sig.sport == 0) &&
	  (sig.dst == 0) && (sig.dport == 0) &&
	  (sig.proto == 0));
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

// Main function, which processes each flow
void
amonProcessing(flow_t flow, int len, long start, long end, int oci)
{
  // Detect if the flow is malformed and reject it
  if (malformed(start) || malformed(end))
    return;

  // Standardize time
  start = int(int(start / parms["interval"])*parms["interval"]);
  end = int(int(end / parms["interval"])*parms["interval"]);

  // Obtain a lock to serialize access to flows
  pthread_mutex_lock (&flows_lock);
  
  // Just link the flow into the structure and process
  // when it is ready. For flows that last a long time
  // multiply the flow and insert into each time interval  
  for (long i = start; i <= end; i+= parms["interval"])
    {
      // Too late for this flow
      if (i < freshtime)
	continue;
      
      // New timestamp, insert into structure
      map<long,time_flow>::iterator it = timeflows.find(i);
      if (it == timeflows.end())
	{
	  time_flow tf;
	  tf.fresh = 0;
	  timeflows.insert(pair<long,time_flow>(i,tf));
	  it = timeflows.find(i);
	}
      // Add the flow and remember that this is a fresh record for this
      // processing interval
      flow_p f={start, end, len, oci, flow};
      it->second.flows.push_back(f);
      it->second.fresh++;
    }

  // Release the lock
  pthread_mutex_unlock (&flows_lock);
}

// Function to detect values higher than mean + parms[numstd] * stdev 
int abnormal(int type, int index, unsigned int timestamp)
{
  // Look up std and mean
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/
		    (stats[hist][n][type][index]-1));
  // Look up current value
  int data;
  if (type == vol)
    data = cells[timestamp].databrick_p[index];
  else
    data = cells[timestamp].databrick_s[index];

  // Volume larger than mean + numstd*stdev is abnormal 
  if (type == vol && data > mean + parms["numstd"]*std)
    return 1;
  // Symmetry larger than mean + numstd*stdev or
  // smaller than mean - numstd*stdev is abnormal 
  else if (type == sym && ((data > mean + parms["numstd"]*std) ||
			   (data < mean - parms["numstd"]*std)))
    return 1;
  else
    return 0;
}

// Update statistics
void update_stats(long timestamp)
{
  // A flow that is before last updatetime, ignore it
  if (timestamp <= updatetime)   
      return;

  // If training is done, update current estimates
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
      updatetime = timestamp;
    }
  // Else training is done and it is time for current values to become
  // historical
  if (timestamp - statstime >= parms["min_train"] && training_done)
    {
      statstime = timestamp;
      for (int j = n; j <= ss; j++)
	for (int k = vol; k <= sym; k++)
	  for(int i = 0; i<BRICK_DIMENSION; i++)
	  {
	    // Check if we have enough samples.
	    // If the attack was long maybe we don't
	    if (stats[cur][n][k][i] <
		parms["min_train"]/parms["interval"]*MIN_SAMPLES)
	      continue;
	    stats[hist][j][k][i] = stats[cur][j][k][i];
	    stats[cur][j][k][i] = 0;
	  }
    }
}

// This function detects an attack
void detect_attack(long timestamp)
{
  // This timeslot is too late for detection
  if (timestamp <= updatetime)
    return;
  // For each bin
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      // Pull average and stdev for volume and symmetry
      double avgv = stats[hist][avg][vol][i];
      double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
      double avgs = stats[hist][avg][sym][i];
      double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));

      // If verbose, output debugging statistics into files
      if (verbose)
	{
	  debug[i]<<timestamp<<" "<<avgv<<" ";
	  debug[i]<<stdv<<" "<<cells[timestamp].databrick_p[i]<<" ";
	  debug[i]<<avgs<<" "<<stds<<" ";
	  debug[i]<<cells[timestamp].databrick_s[i]<<" ";
	  debug[i]<<cells[timestamp].wfilter_p[i]<<"  ";
	  debug[i]<<cells[timestamp].wfilter_s[i]<<"  ";
	  debug[i]<<is_attack[i]<<endl;
	}

      // If both volume and asymmetry are abnormal and training has completed
      if (training_done && abnormal(vol, i, timestamp)
	  && abnormal(sym, i, timestamp))
	{
	  if (verbose)
	    cout<<timestamp<<" abnormal for "<<i<<" points "<<is_abnormal[i]<<" oci "<<cells[timestamp].databrick_s[i]<<" ranges " <<avgs<<"+-"<<stds<<", vol "<<cells[timestamp].databrick_p[i]<<" ranges " <<avgv<<"+-"<<stdv<<endl;

	  // Increase abnormal score, but cap at attack_high/interval
	  if (is_abnormal[i] < int(parms["attack_high"]/parms["interval"]))
	      is_abnormal[i]++;

	  // If abnormal score is above attack_low/interval
	  if (is_abnormal[i] >= int(parms["attack_low"]/parms["interval"])
	      && (is_attack[i] == 0))
	    {
	      // Signal attack detection 
	      is_attack[i] = 1;
	      reported[i] = 0;
	      if (verbose)
		cout<<"AT: Attack detected on "<<i<<" but not reported yet, timestamp "<<timestamp<<endl;

	      // Find closest timestamp and calculate signatures
	      int s = cells[timestamp].databrick_s[i];
	      long t = calcSignature(timestamp, i, s);
	      if (t > 0)
		{		 		  
		  // Find the best signature
		  flow_t bestsig = {0,0,0,0,0};
		  int oci = 0;
		  int maxoci = 0;
		  int totoci = cells[t].databrick_s[i];

		  // Go through candidate signatures
		  for (map<int,flow_p>::iterator sit = samples[t].bins[i].flows.begin(); sit != samples[t].bins[i].flows.end(); sit++)
		    {
		      // Print out each signature for debugging
		      if (verbose)
			cout<<"SIG: "<<i<<" candidate "<<printsignature(sit->second.flow)<<" v="<<sit->second.len<<" o="<<sit->second.oci<<" toto="<<totoci<<endl;
		      // This signature covers more than the maximum, remember
		      // this new maximum
		      if (abs(samples[t].bins[i].flows[sit->first].oci) > abs(maxoci))
			maxoci = samples[t].bins[i].flows[sit->first].oci;
		      // Is it a more specific signature with also much
		      // more coverage
		      if (abs(samples[t].bins[i].flows[sit->first].oci) > HMB*abs(oci) ||
			  (HMB*abs(samples[t].bins[i].flows[sit->first].oci) > abs(maxoci) && bettersig(sit->second.flow, bestsig)))
			{
			  bestsig = sit->second.flow;
			  oci = sit->second.oci;
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
			  stat_f sf = {t, cells[t].databrick_p[i], cells[t].databrick_s[i], bestsig,m1,m2, 0};
			  signatures.insert(pair<int, stat_f>(i,sf));
			}
		      else
			{
			  // or replace the signature already there
			  // and reset all the stats
			  signatures[i].sig = bestsig;
			  signatures[i].nflows = 0;
			  signatures[i].matchedflows.clear();
			  signatures[i].reverseflows.clear();
			  signatures[i].timestamp = t;
			  signatures[i].vol = cells[t].databrick_p[i];
			  signatures[i].oci = cells[t].databrick_s[i];
			}
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
	      // There were no samples to be found
	      else
		{
		  if (verbose)
		    cout << "AT: Did not find any samples for attack on bin "
			 <<i<<endl;
		  is_attack[i] = 0;
		}
	    }
	}
      // Training is completed and both volume and symmetry are normal
      else if (training_done && !abnormal(vol, i, timestamp) &&
	       !abnormal(sym, i, timestamp))
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
			 << " time " << timestamp <<" sig "
			 <<printsignature(signatures[i].sig)<<endl;
		  // Write the end of the attack into alerts
		  ofstream out;
		  out.open("alerts.txt", std::ios_base::app);
		  out << "STOP "<<i<<" "<<timestamp<<endl;
		  out.close();
		}
	      // Delete signature if exists
	      if (signatures.find(i) != signatures.end())
		signatures.erase(i);
	      // Reset attack and reported signals
	      is_attack[i] = 0;
	      reported[i] = 0;
	    }
	}
    }
}

// Go through flows for a given timestamp and collect statistics
void processFlows(long timestamp)
{
  times.push_back(timestamp);

  int d_bucket = 0, s_bucket = 0;	    // indices for the databrick 

  // Create an empty cell
  cell c;
  memset(c.databrick_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c.databrick_s, 0, BRICK_DIMENSION*sizeof(int));
  memset(c.wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
  memset(c.wfilter_s, 0, BRICK_DIMENSION*sizeof(int));	  

  // Serialize access to stats
  pthread_mutex_lock (&cells_lock);

  // Go through each flow
  map<long,cell>::iterator it = cells.find(timestamp);
  for (vector<flow_p>::iterator fit=timeflows[timestamp].flows.begin();  fit != timeflows[timestamp].flows.end(); fit++)
    {
      s_bucket = hash(fit->flow.src); 
      d_bucket = hash(fit->flow.dst); 

      // Insert a bin if it does not exist
      if (it == cells.end())
	{
	  cells.insert(pair<long,cell>(timestamp,c));
	  it = cells.find(timestamp);
	}
      
      // add bytes to payload databrick for dst
      it->second.databrick_p[d_bucket] += fit->len;
      // add oci to symmetry databrick for dst
      it->second.databrick_s[d_bucket] += fit->oci;

      // add bytes to payload databrick for dst
      it->second.wfilter_p[d_bucket] += fit->len;
      // add oci to symmetry databrick for dst
      it->second.wfilter_s[d_bucket] += fit->oci;
	  
      if(fit->flow.proto == UDP) 
      {   // add oci to symmetry databrick for src 
          it->second.databrick_s[s_bucket] += fit->oci;
          it->second.wfilter_s[s_bucket] += fit->oci;
      }    
      else 
      {   // subtract oci from symmetry databrick for src 
          it->second.databrick_s[s_bucket] -= fit->oci;
          it->second.wfilter_s[s_bucket] -= fit->oci;
      }
      
      // If we did not report this attack, collect some flows
      // that match a signature for the attack to see if we would
      // have too many false positives
      // First deal with reverse flow matching
      if (is_attack[s_bucket] && reported[s_bucket] == 0)
	{
	  flow_t rflow = {fit->flow.dst, fit->flow.dport,
			  fit->flow.src, fit->flow.sport, fit->flow.proto};
	  
	  if (match(rflow, signatures[s_bucket].sig))
	    {
	      if (signatures[s_bucket].reverseflows.find(rflow) ==
		  signatures[s_bucket].reverseflows.end())
		{
		  signatures[s_bucket].reverseflows.insert(pair<flow_t, int>(rflow,0));
		}
	      if (fit->oci == 0)
		signatures[s_bucket].reverseflows[rflow] ++;
	      else
		signatures[s_bucket].reverseflows[rflow] += abs(fit->oci);
	    }
	}

      // Now deal with exact flow matching
      if (is_attack[d_bucket] && reported[d_bucket] == 0)
	{
	  if (match(fit->flow, signatures[d_bucket].sig))
	    {
	      if (fit->flow.proto == TCP && fit->oci == 0)
		signatures[d_bucket].nflows++;
	      else
		signatures[d_bucket].nflows+= abs(fit->oci);

	      if (signatures[d_bucket].matchedflows.find(fit->flow)
		  == signatures[d_bucket].matchedflows.end())
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
	      if (signatures[d_bucket].nflows >= SIG_FLOWS)
		{
		  int good = 0, bad = 0;
		  
		  for(map <flow_t, int>::iterator mit = signatures[d_bucket].matchedflows.begin(); mit != signatures[d_bucket].matchedflows.end(); mit++)
		      {
			// Symmetry makes a flow good only if it is UDP or TCP+PSH
			if ((signatures[d_bucket].reverseflows.find(mit->first) != signatures[d_bucket].reverseflows.end() &&
			     mit->first.proto == UDP)
			    || (mit->first.proto == TCP && mit->second == 0))
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
		  if (verbose)
		    cout<<"SIG: "<<d_bucket<<" good "<<good<<" bad "<<bad<<" sig "<<printsignature(signatures[d_bucket].sig)<<endl;
		    if ((float)good/(good+bad) <= parms["spec_thresh"])
		      {
			long t = signatures[d_bucket].timestamp;
			float rate = (float)signatures[d_bucket].vol*8/1024/1024/1024;
			
			// Dump alert into a file
			ofstream out;
			out.open("alerts.txt", std::ios_base::app);
			out<<"START "<<d_bucket<<" "<<t<<" "<<rate;
			out<<" "<<signatures[d_bucket].oci<<" ";
			out<<good<<" "<<bad;
			out<<" "<<printsignature(signatures[d_bucket].sig)<<endl;
			out.close();
			// Flip the reported bit
			reported[d_bucket] = 1;
		      }
		    else
		      {
			// Try again Mr Noodle, this was not a good signature
			if (verbose)
			  cout<<"SIG: attack on "<<d_bucket<<" signature was not specific enough "<<endl;
			is_attack[d_bucket] = 0;
			signatures.erase(d_bucket);
		      }
		  }
	      }
	}
      // If this is a reported attack and we're verbose, let's collect
      // some statistics on how much we're helping
      if (reported[d_bucket] == 1 && verbose)
	{	
	  if (match(fit->flow, signatures[d_bucket].sig))
	    {
	      // Undo changes for wfilter 
	      it->second.wfilter_p[d_bucket] -= fit->len;	
	      it->second.wfilter_s[d_bucket] -= fit->oci;	
	      it->second.wfilter_s[s_bucket] += fit->oci;
	    }
	}

      // If we've not yet signaled an attack but the flow's oci is of the
      // same sign as the stats for its bin, collect this flow in samples
      // for possible signature later
      if (!is_attack[d_bucket] && training_done && fit->oci != 0
	  && sgn(fit->oci) == sgn(it->second.databrick_s[d_bucket]))
	  {
	    flow_p f=*fit;
	    addSample(d_bucket, f, timestamp);
	  }
      // Release the lock 
      pthread_mutex_unlock (&cells_lock);
    }
  // Figure out if we've completed the training
  int diff = timestamp - firsttime;

  if(diff > parms["min_train"] && !training_done)
    {
      cout<<"Training has completed"<<endl;
      training_done = 1;
      statstime = timestamp;
    }

  // If we did not, let's do the learning
  if (!training_done)
    {
      for (int i=0;i<BRICK_DIMENSION;i++)
	{
	  for (int j=vol; j<=sym; j++)
	    {
	      int data;
	      if (j == vol)
		data = it->second.databrick_p[i];
	      else
		data = it->second.databrick_s[i];

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
      //update_stats(it->first); Jelena check
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
	  cells.erase(times[0]);
	  times.erase(times.begin());
	}
    }
  // Erase samples if any
  if (samples.find(it->first) != samples.end())
    {
      samples.erase(it->first);
    }
}

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

  // Get source and destination IP and port and protocol 
  flow_t flow = {0,0,0,0};
  int proto = atoi(line+delimiters[4]);
  flow.src = strtol(line+delimiters[8], &tokene, 10);
  flow.sport = atoi(line+delimiters[9]); 
  flow.dst = strtol(line+delimiters[13], &tokene, 10);
  flow.dport = atoi(line+delimiters[14]); 
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
  while (1)
    {
      long curtime = 0;
      int fresh = 0;

      // Serialize access to flows
      pthread_mutex_lock (&flows_lock);

      
      // Find timestamps that are not fresh
      for (map<long,time_flow>::iterator it=timeflows.begin(); it != timeflows.end(); )
	{
	  curtime = it->first;
	  int diff = curtime - firsttime;

	  if (it->second.fresh || fresh)
	    {
	      // Or they are fresh but they have enough flows
	      if (fresh == 0 || (fresh <= MIN_FRESH &&
				 it->second.flows.size() >= MIN_FLOWS))
		{
		  fresh = 1;
		  freshtime = curtime;
		}
	      it->second.fresh = 0;
	      it++;
	      continue;
	    }
	  else
	    {
	      // Process this batch of flows
	      // Collect stats, detect attack, etc
	      processFlows(it->first);
	      timeflows.erase(it++);
	    }
	}
      // Release access to flows
      pthread_mutex_unlock (&flows_lock);

      // Check if there is an attack that was waiting
      // a long time to be reported. Perhaps we had too specific
      // signature and we will never collect enough matches
      // Serialize access to stats
      pthread_mutex_lock (&cells_lock);

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
	      if (verbose)
		cout<<"AT: attack on "<<sit->first<<" not enough matching flows "<<sit->second.nflows<<endl;
	      is_attack[sit->first] = 0;
	      signatures.erase(sit++);
	    }
	  else
	    sit++;
	}
      // Release the lock to access stats
      pthread_mutex_unlock (&cells_lock);
      // Sleep a bit and try again
      sleep(1);
    }
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
	  training_done = 1;
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
  printf ("-v                             Verbose\n");
}


// Main program
int main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  // Parse configuration
  parse_config (parms);
  // Load service port numbers
  loadservices("services.txt");
  
  char c, buf[32];
  char *file_in = NULL;

  
  while ((c = getopt (argc, argv, "hvlr:")) != '?')
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
	  file_in = strdup (optarg);
	  break;
	case 'l':
	  load_history();
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
  // Prepare debug files
  if (verbose)
    for (int i = 0; i < BRICK_DIMENSION; i++)
      {
	sprintf(filename,"%d.debug", i);
	debug[i].open(filename);
	debug[i]<<"#timestamp mean_vol std_vol cur_vol mean_as std_as cur_as vol_fil as_fil attack\n";
      }

  pthread_t thread_id;
  pthread_create (&thread_id, NULL, reset_transmit, NULL);

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

      // Go through tracefiles and read each one
      for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
      {
	const char* file = vit->c_str();
	
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
	    amonProcessingNfdump(line, epoch);
	  }
	cout<<"Done with the file "<<file<<" time "<<time(0)<<endl;
	pclose(nf);
      }
    }
  save_history();
  return 0;
}
