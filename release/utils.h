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

#ifndef __UTILS_H
#define __UTILS_H

#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <map>

using namespace std;

#define BRICK_DIMENSION 257       // How many bins we have. This should NOT be a power of 2
#define REPORT_THRESH 30
#define MIN_FLOWS 100000          // This parameter and the next ensure we report on time intervals that
#define MIN_FRESH 10              // have seen most of their records
#define HMB 1.1                   // This is how much more a less specific signature should catch to be accepted
#define MAXLINE 255               // Maximum length for reading strings
#define AR_LEN 30                 // How many delimiters may be in an array
#define MAX_DIFF 10               // How close should a timestamp be to the one where attack is detected

enum protos {TCP=6, UDP=17};       // Transport protocols we work with. We ignore other traffic

// 5-tuple for the flow
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
  
  bool operator==(const flow_t& rhs) const
  {
    return (src == rhs.src) && (dst == rhs.dst) && (sport == rhs.sport) && (dport == rhs.dport) && (proto == rhs.proto);
  }
};

// This wraps a flow and keeps some statistics
struct flow_p
{
  long start;
  long end;
  int len;
  int oci;
  flow_t flow;
};

// This holds all the flows for a given time interval. 
struct time_flow
{
  vector<flow_p> flows;
  int fresh;
};

// This structure keeps some statistics on a candidate signature
struct stat_f
{
  long timestamp;
  int vol;
  int oci;
  flow_t sig;
  map <flow_t,int> matchedflows;
  map <flow_t,int> reverseflows;
  int nflows;
};

// Some statistics for the flow
struct stat_r
{
  int vol;
  int oci;
};

// A sample of flows that are used to derive a signature for the attack
struct sample_p
{
  map<int, flow_p> flows;
  map<flow_t,stat_r> signatures;
};

// Holds the samples for each bin
struct sample
{
  sample_p bins[BRICK_DIMENSION];
};

// Some function prototypes. Functions are defined in utils.cc
int hash(u_int32_t ip);
int sgn(double x);
int bettersig(flow_t a, flow_t b);
string printsignature(flow_t s);

#endif
