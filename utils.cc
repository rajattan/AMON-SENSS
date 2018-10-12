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

#include "utils.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include <fstream>

// We need this so sort would work
namespace patch
{
  template < typename T > std::string to_string( const T& n )
  {
    std::ostringstream stm ;
    stm << n ;
    return stm.str() ;
  }
}

// Convert string to address
unsigned int todec(string ip)
{
  int res = 0;
  int dec = 0;
  for (int i=0; i<strlen(ip.c_str()); i++)
    if (isdigit(ip[i]))
      dec = dec*10+(ip[i]-'0');
    else
      {
	res = res*256+dec;
	dec = 0;
      }
  res = res*256+dec;
  return res;
}


// Convert address to IP string
string toip(unsigned int addr)
{
  string out="";
  int div = 256*256*256;
  while (div > 0)
    {
      unsigned int r = (unsigned int)addr/div;
      addr = addr - r*div;
      div /= 256;
      if (out != "")
	out = out + ".";
      out = out + patch::to_string(r);
    }
  return out;
}

// Print out signature/flow
string printsignature(flow_t s)
{
  string out;
  if (s.src != 0)
    out += ("src ip "+ toip(s.src));
  if (s.sport != 0)
    {
      if (out.size() > 0)
	out += " and ";
      out += ("src port " + patch::to_string(s.sport));
    }
  if (out.size() > 0)
    out += " and ";
  out += ("dst ip " + toip(s.dst));
  if (s.dport != 0)
    {
      if (out.size() > 0)
	out += " and ";
      out += ("dst port " + patch::to_string(s.dport));
    }
  if (s.proto == TCP || s.proto == UDP)
    {
      if (out.size() > 0)
	out += " and ";
      if (s.proto == TCP)
	out += "proto tcp";
      else
	out += "proto udp";
    }
  return out;
}

// Sign of a number
int sgn(double x)
{
  if (x<0)
    return -1;
  else if (x>0)
    return 1;
  else
    return 0;
}

// Is the signature all zeros (i.e. the default signature)
int zeros(flow_t a)
{
  return (a.src == 0) + (a.sport == 0) + (a.dst == 0) + (a.dport == 0) + (a.proto == 0);
}

// A signature is better if it has more items defined or if it has ports and srcip 
int bettersig(flow_t a, flow_t b)
{
  if (zeros(a) < zeros(b) ||
      ((zeros(a) == zeros(b)) && (a.src > b.src) &&
       (a.sport > b.sport || a.dport > b.dport)))
    return 1;
  else
    return 0;
}

// Simple hash function
// Take the second and third bytes, convert into int and mod
// Use service port instead of the last byte
int myhash(u_int32_t src, unsigned short sport, u_int32_t dst, unsigned short dport, int isdst)
{
  int o = -1;
  // client traffic to our prefixes, store in the first half
  if (islocal(dst))
    {
      if(isservice(dport))
	{
	  if (isdst)
	    o = (((dst &  0x00ffff00)+dport) % BRICK_HALF)+BRICK_HALF;
	  else
	    o = -1;
	}
      // service traffic to our prefixes, store in the second half
      else if (isservice(sport))
	{
	  if (isdst)
	    o = (((dst &  0x00ffff00)+dport) % BRICK_HALF);
	  else
	    o = -1;
	}
    }
  else if (islocal(src))
    {
      // client traffic from our prefixes, store in the second half
      if(isservice(dport))
	{
	  if (!isdst)
	    o = (((src &  0x00ffff00)+dport) % BRICK_HALF);
	  else
	    o = -1;
	}
      // service traffic from our prefixes, store in the first half
      else if (isservice(sport))
	{
	  if (!isdst)
	    o = (((src &  0x00ffff00)+sport) % BRICK_HALF)+BRICK_HALF;
	  else
	    o = -1;
	}
    }
  return o;  
}

map<int,int> services;
int loadservices(const char* fname)
{
  ifstream inFile;
  int i = 0;
  inFile.open(fname);
  int port;
  while(inFile >> port)
    services.insert(pair<int, int>(port, i++));
  return services.size();
}

// Is this a service port?
int isservice(int port)
{
  return(services.find(port) != services.end());
}

// Load local prefixes
map <u_int32_t, int> localprefs;
int loadprefixes(const char* fname)
{
  ifstream inFile;
  int i = 0;
  inFile.open(fname);
  char ip[30];
  char pref[30];
  char mask[30];
  while(inFile >> pref)
    {
      char* ptr = strstr(pref, "/");
      if (ptr == NULL)
	continue;
      *ptr=0;
      localprefs.insert(pair<u_int32_t, int>(todec(pref), atoi(ptr+1)));
      cout<<"Inserted "<<todec(pref)<<" mask "<<atoi(ptr+1)<<endl;
    }
  cout<<"Done";
  return localprefs.size();
}

// Is this a local prefix?
int islocal(u_int32_t ip)
{
  for (map<u_int32_t, int>::iterator it = localprefs.begin(); it != localprefs.end(); it++)
    {
      if ((ip & (~0 << (32 - it->second))) == it->first)
	return true;
      else
	return false;
    }
}
