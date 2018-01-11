#include "utils.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sstream>

namespace patch
{
  template < typename T > std::string to_string( const T& n )
  {
    std::ostringstream stm ;
    stm << n ;
    return stm.str() ;
  }
}

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

string printsignature(sig_b s)
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
  if (s.proto == 6 || s.proto == 17)
    {
      if (out.size() > 0)
	out += " and ";
      if (s.proto == 6)
	out += "proto tcp";
      else
	out += "proto udp";
    }
  return out;
}

int sgn(double x)
{
  if (x<0)
    return -1;
  else if (x>0)
    return 1;
  else
    return 0;
}

int zeros(sig_b a)
{
  return (a.src == 0) + (a.sport == 0) + (a.dst == 0) + (a.dport == 0) + (a.proto == 0);
}

/* A signature is better if it has more items defined or if it has ports and srcip */
int bettersig(sig_b a, sig_b b)
{
  if (zeros(a) < zeros(b) ||
      ((zeros(a) == zeros(b)) && (a.src > b.src) &&
       (a.sport > b.sport || a.dport > b.dport)))
    return 1;
  else
    return 0;
}

int sha_hash(u_int32_t ip)
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

  return (unsigned int)rvalue % BRICK_DIMENSION;

}
