/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.19.4.7 2010/06/16 08:40:11 dembour Exp $
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

#include <time.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#include "mycrypto.h"
#include "server.h"
#include "dns.h"
#include "list.h"
#include "requests.h"
#include "base32.h"
#include "myrand.h"
#include "socket.h"
#include "queue.h"
#include "debug.h"
#include "log.h"
#include "queue.h"
#include "session.h"

/**
 * @brief try to connect a client to a ressource
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[out] packet where to write the packet request
 * @param[out] socket socket created
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		connect_resource(t_conf *conf, t_request *req, t_packet *packet, t_simple_list *client, int *sd)
{
    t_list		*list_resource;
    char		*resource, *tmp;
    int			len;
  
    resource = ((char *)packet) + PACKET_LEN;
    if (!(len = strlen(resource)))
        return (-1);
    DPRINTF(1, "Client request for tunneling \'%s\'\n", resource);
  
    tmp = strchr(resource, ':');
	if (tmp == NULL)
	{   
        // Client runs in -R mode
        client->is_local_port_forwarding = false;
        client->port = atoi(resource);
	}
    else
    {
        // Client runs in -L mode
        tmp[0] = '\0';
        tmp++;
        client->is_local_port_forwarding = true;
        client->port = atoi(tmp);
        client->address = inet_addr(resource);
    }
    
    if (client->is_local_port_forwarding)
    {
        DPRINTF(1, "Connecting to host %s port %d\n", resource, client->port);
        if (! connect_socket(client->address, client->port, sd))
            return (0);
    }
    else
    {
        DPRINTF(1, "Binding to port %d\n", client->port);
        if (! bind_socket_tcp(client->port, sd))
            return (0);
    }
        
    packet->type = ERR;
    send_ascii_reply(conf, req, packet, ERR_CONN_REFUSED);
    return (-1);
}


/**
 * @brief try to bind a client to a ressource
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[in] packet packet request
 * @param[in] client client to bind
 * @retval 0 on success
 * @retval -1 on error
 **/

int			bind_user(t_conf *conf, t_request *req, t_packet *packet, t_simple_list *client)
{
    int			sd;
    char			*resource;
    char			*compress;

    if (connect_resource(conf, req, packet, client, &sd))
        return (-1);
    resource = ((char *)packet) + PACKET_LEN;
    client_update_timer(client);
    if (!(compress = jump_end_query(req, 
				   GET_16(&(((struct dns_hdr *)req->data)->qdcount)), req->len)))
    {
        fprintf(stderr, "invalid reply\n");
        return (-1);
    }

    if (client->is_local_port_forwarding)
    {
        client->sd = -1;
        client->sd_tcp = sd;
    }
    else
    {
        client->sd = sd;
        client->sd_tcp = -1;
    }

    packet->type = OK;
    return (send_ascii_reply(conf, req, packet, ""));
}


/**
 * @brief checks if new connection was established to client's socket
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[in] packet packet request
 * @param[in] client client to bind
 * @retval 0 on success
 * @retval -1 on error
 **/

int			check_connected(t_conf *conf, t_request *req, t_packet *packet, t_simple_list *client)
{
    client_update_timer(client);
    if (client->sd_tcp == -1)
        packet->type = NOP;
    else
        packet->type = OK;
    
    LOG("Check connected client id: 0x%x res is %d", client->session_id, packet->type);
    return (send_ascii_reply(conf, req, packet, ""));
}

int			disconnected(t_conf *conf, t_request *req, t_packet *packet, t_simple_list *client)
{
    LOG("Got that remote connection closed: 0x%x", client->session_id);
	if (client->sd != -1)
    {
	    close(client->sd);
        client->sd = -1;
    }
	if (client->sd_tcp != -1)
    {
	    close(client->sd_tcp);
        client->sd_tcp = -1;
    }
	delete_client(conf, client);
        
    return 0;
}


/**
 * @brief try to authenticate (more a indentification) a client with CHAP
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[in] packet packet request
 * @retval 0 on success
 * @retval -1 on error
 **/

int		login_user(t_conf *conf, t_request *req, t_packet *packet)
{
  char		*data;
  t_simple_list	*client;
  char		 buffer[SHA1_SIZE*2+1];
  
  memset(buffer, 0, sizeof(buffer));
  if (req->len <= PACKET_LEN)
    return (-1);
  data =  ((char *) packet) + PACKET_LEN;
  client = find_client_by_session_id(conf, packet->session_id);
  if (client)
    {	
      if (conf->key)
	{
	  sign_challenge(client->control.challenge, CHALLENGE_SIZE, conf->key, (char *)&buffer, sizeof(buffer));
	  if (strncmp(buffer, data, SHA1_SIZE*2))
	    {
	      packet->type = ERR;
	      LOG("Authentication failed");
	      send_ascii_reply(conf, req, packet, ERR_AUTH_FAILED);	        
	      return (delete_client(conf, client));
	    }
	}
      client_update_timer(client);
      client->control.authenticated = 1;
      client->sd_tcp = -1;
      client->sd = -1;
      packet->type = OK;
      return (send_ascii_reply(conf, req, packet, ""));
    }
  if (!(client = create_session(conf, req, packet)))
    return (-1);
  alphanum_random(client->control.challenge, CHALLENGE_SIZE);
  packet->type = OK;
  packet->session_id = client->session_id;
  return (send_ascii_reply(conf, req, packet, client->control.challenge));
}

