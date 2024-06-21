#ifndef __ICMP_H__
#define __ICMP_H__

#include <windows.h>
#include <winsock2.h>
#include <ikcp.h>
#include <stdio.h>

#define PREPEND_SIZE ( sizeof( IP_HEADER ) + sizeof( ICMP_HEADER ) )
#define C_PTR( x )   ( ( char* )( x ) )

typedef struct _IP_HEADER
{
    unsigned int   ihl     : 4;
    unsigned int   version : 4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
} IP_HEADER, *PIP_HEADER;

typedef struct _ICMP
{
    SOCKET             sock;
    ikcpcb*            ikcp;
    struct sockaddr_in dest;
    int                id;
    int                seq;
} ICMP, *PICMP;

typedef struct _ICMP_HEADER
{
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HEADER, *PICMP_HEADER;

PICMP icmp_init( char* host );
int   icmp_send( PICMP icmp, unsigned char* buf, int len );
int   icmp_recv( PICMP icmp, unsigned char* buf, int len );
void  icmp_free( PICMP icmp );

#endif  __ICMP_H__
