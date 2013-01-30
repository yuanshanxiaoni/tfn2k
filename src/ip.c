/*
 * Tribe FloodNet - 2k edition
 * by Mixter <mixter@newyorkoffice.com>
 *
 * ip.c - low level IP functions
 *
 * This program is distributed for educational purposes and without any
 * explicit or implicit warranty; in no event shall the author or
 * contributors be liable for any direct, indirect or incidental damages
 * arising in any way out of the use of this software.
 *
 */

#include "tribe.h"
#include "ip.h"

unsigned long
resolve (char *host)
{
  struct hostent *he;
  struct sa tmp;
  if (isip (host))
    return (inet_addr (host));
  he = gethostbyname (host);
  if (he)
    {
      memcpy ((caddr_t) & tmp.add, he->h_addr, he->h_length);
    }
  else
    return (0);
  return (tmp.add);
}

char *
ntoa (u32 in)
{
  struct in_addr ad;
  ad.s_addr = in;
  return (inet_ntoa (ad));
}

int
isip (char *ip)
{
  int a, b, c, d;
  sscanf (ip, "%d.%d.%d.%d", &a, &b, &c, &d);
  if (a < 0)
    return 0;
  if (a > 255)
    return 0;
  if (b < 0)
    return 0;
  if (b > 255)
    return 0;
  if (c < 0)
    return 0;
  if (c > 255)
    return 0;
  if (d < 0)
    return 0;
  if (d > 255)
    return 0;
  return 1;
}

u16
cksum (u16 * buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

unsigned short
ip_sum (addr, len)
     unsigned short *addr;
     int len;
{
  register int nleft = len;
  register unsigned short *w = addr;
  register int sum = 0;
  unsigned short answer = 0;

  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}
