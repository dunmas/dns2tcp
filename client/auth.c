/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.19.4.3 2010/01/06 12:50:40 dembour Exp $
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

#include <string.h>
#include <stdio.h>       
#include <stdbool.h>

#include "client.h"
#include "dns.h"
#include "myerror.h"
#include "list.h"
#include "requests.h"
#include "socket.h"
#include "base32.h"
#include "myrand.h"
#include "session.h"
#include "myerror.h"
#include "debug.h"
#include "rr.h"

/**
 * @brief connect to a specific ressource
 * @param[in] conf configuration
 * @param[in] session_id session identifier
 * @retval 0 on success
 * @retval 1 on error
 **/

uint16_t		connect_resource(t_conf *conf, uint16_t session_id)
{
	char			domain[MAX_DNS_LEN + 1];
	char			*resource;
	char			buffer[MAX_DNS_LEN + 1];
	int			len;
	t_request		request;
	t_packet		*packet;

	if (create_simple_req(conf, &request, CONNECT, (char *)&domain, session_id))
		return(-1);
	resource = &request.req_data[PACKET_LEN];
	DPRINTF(1, "Connect to resource \"%s\"\n", conf->resource);
	strncpy(resource, conf->resource, sizeof(request.req_data) - PACKET_LEN - 1);
	request.len = PACKET_LEN + strlen(conf->resource);
	if ((len = transceive_query(conf, &request, (char *)&buffer, sizeof(buffer) - 1)) == -1)
		return (1);
	buffer[len] = 0;
	packet = (t_packet *)&buffer;
	if (packet->type != OK)
		fprintf(stderr, "Error : %s\n", (char *)(packet + 1));
	return (packet->type != OK);
}

uint16_t		check_resource_connected(t_conf *conf, uint16_t session_id)
{
	char			domain[MAX_DNS_LEN + 1];
	char			*resource;
	char			buffer[MAX_DNS_LEN + 1];
	int			len;
	t_request		request;
	t_packet		*packet;

	if (create_simple_req(conf, &request, CONNECTED, (char *)&domain, session_id))
		return(-1);
	resource = &request.req_data[PACKET_LEN];
	DPRINTF(1, "Check if connected to resource \"%s\"\n", conf->resource);
	strncpy(resource, conf->resource, sizeof(request.req_data) - PACKET_LEN - 1);
	request.len = PACKET_LEN + strlen(conf->resource);
	if ((len = transceive_query(conf, &request, (char *)&buffer, sizeof(buffer) - 1)) == -1)
		return (1);
	buffer[len] = 0;
	packet = (t_packet *)&buffer;
	if (packet->type == NOP)
		return 2;
	if (packet->type == OK)
		return 0;

	fprintf(stderr, "Error : %s\n", (char *)(packet + 1));
	return (1);
}

uint16_t		disconnect_client(t_conf *conf, uint16_t session_id)
{
	char			domain[MAX_DNS_LEN + 1];
	char			*resource;
	t_request		request;

	if (create_simple_req(conf, &request, DISCONNECTED, (char *)&domain, session_id))
		return(-1);
	resource = &request.req_data[PACKET_LEN];
	DPRINTF(1, "Send client disconnected\n");
	strncpy(resource, conf->resource, sizeof(request.req_data) - PACKET_LEN - 1);
	request.len = PACKET_LEN + strlen(conf->resource);
	send_query(conf, &request);
	return 0;
}

