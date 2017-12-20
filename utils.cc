#include "utils.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>


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
