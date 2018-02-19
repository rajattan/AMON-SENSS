/*
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
// Take the last two bytes, convert into int and mod BRICK_DIMENSION 
int hash(u_int32_t ip)
{
  int o = (ip &  0x000ffff) % BRICK_DIMENSION;
  return o;  
}
  
