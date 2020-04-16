/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.c,v 1.18.4.4 2010/02/10 15:29:51 dembour Exp $
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/socket.h>     
#include <sys/types.h>
#include <netdb.h>
#endif

#include "dns.h"
#include "server.h"
#include "myerror.h"
#include "debug.h"
#include "socket.h"


/**
 * @brief listen on wanted interfaces
 * @param[in] conf configuration
 **/

int				bind_socket_dns(t_conf *conf)
{
  int				ret;
  union sockaddr_u		su;
  struct addrinfo		*res, hints;
  socklen_t			slen;

  memset(&su, 0, sizeof(su));

  slen = sizeof(struct sockaddr_in);
  if (conf->my_ip)
    {
      DPRINTF(1, "Listening on %s:%d for domain %s\n", conf->my_ip, 
	      conf->port, conf->my_domain);
      memset(&hints, 0, sizeof(hints));
      hints.ai_flags    = AI_CANONNAME;
      hints.ai_family   = PF_UNSPEC;
      hints.ai_socktype = SOCK_DGRAM;
      res = NULL;
      if ((ret = getaddrinfo(conf->my_ip, NULL, &hints, &res)) || !res)
        {
          MYERROR("getaddrinfo: %s\n", gai_strerror(ret));
          return (-1);
        }
      switch (res->ai_family) {
        case AF_INET:
          memcpy(&su.in.sin_addr,
		 &((struct sockaddr_in *) res->ai_addr)->sin_addr,
		 sizeof(struct in_addr));
	  su.in.sin_port = htons(conf->port);
	  su.in.sin_family = res->ai_family;
	  break;
	  /* Not supported
	case AF_INET6:
	  memcpy(&su.in6.sin6_addr,
	         &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
		 sizeof(struct in6_addr));
	  su.in6.sin6_port = htons(conf->port);
	  su.in6.sin6_family = res->ai_family;
          slen = sizeof(struct sockaddr_in6);
	  break;
	  */

	default:
          freeaddrinfo(res);
	  return (-1);
      }
      freeaddrinfo(res);
    }
  else
    {
      su.in.sin_family = AF_INET;
      su.in.sin_addr.s_addr = INADDR_ANY;
      su.in.sin_port = htons(conf->port);
      DPRINTF(1, "Listening on 0.0.0.0:%d for domain %s\n", conf->port, 
	      conf->my_domain);
    }
  if ((conf->sd_udp = socket(su.in.sin_family, SOCK_DGRAM, 0)) < 0)
    {
      MYERROR("socket error");
      return (-1);
    }
  if (bind(conf->sd_udp, &su.sockaddr, slen) < 0)
    {
      close(conf->sd_udp);
      MYERROR("bind error");
      return (-1);
    }
  return (0);      
}


/**
 * @brief non blocking IO
 * @param[in] sd socket
 * @retval 0 on success
 * @retval -1 on error
 **/

static int	set_nonblock(socket_t sd)
{
#ifndef _WIN32
  int		opt;

  if ((opt = fcntl(sd, F_GETFL)) == -1)
    return (-1);
  if ((opt = fcntl(sd, F_SETFL, opt|O_NONBLOCK)) == -1)
    return (-1);
#endif
  return (0);
}



/**
 * @brief connect to a resource
 * @param[in] port port to bind to
 * @param[out] socket descriptor
 **/

int			bind_socket_tcp(uint16_t port, int *sd)
{
  int ret;
  int  optval;
  char *host, *end;
  struct sockaddr_storage ss;
  struct addrinfo *res, *ptr;
  struct sockaddr_in addr;


  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if ((*sd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    MYERROR("socket error %hd", port);
    return (-1);
  }
  if (!setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
  {
    if (bind(*sd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
  	  perror("bind error");
	  return (-1);
	}
    if ((!set_nonblock(*sd)) && (!listen(*sd, 10)))
	{
	  fprintf(stderr, "Listening on port : %d\n", port);
	  return (0);
	}
  }
  MYERROR("Socket_error");
  return (-1);      
}


int			connect_socket(in_addr_t address, uint16_t port, int *sd)
{
    struct sockaddr_in sa;

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = address; //htonl(address);
	sa.sin_family = AF_INET;
    
    if ((*sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        MYERROR("socket error");
        return (-1);
	}
    DPRINTF(1, "sd = %d  port = %d  address = %d\n", *sd, port, address);
	if (connect(*sd, (struct sockaddr *) &sa, sizeof(struct sockaddr_in)) < 0)
	{
		perror("socket connect error");
		return (-1);
	}
	if (!set_nonblock(*sd))
	{
		fprintf(stderr, "Connected to port : %d\n", port);
		return (0);
	}

    MYERROR("connect error");
    close(*sd);
    *sd = -1;
    return (-1);
}
