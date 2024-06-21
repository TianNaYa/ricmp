#include <icmp.h>

static unsigned short checksum( void *data, int len ) 
{
    unsigned short *buf = data;
    unsigned int    sum = 0;

    for ( sum = 0; len > 1; len -= 2 )
    {
        sum += *buf++;
    }

    if ( len == 1 )
    {
        sum += *( unsigned char * )buf;
    }

    sum =  ( sum >> 16 ) + ( sum & 0xFFFF );
    sum += ( sum >> 16 );

    return ~sum;
}

static int initialize_winsock( void )
{
    WSADATA wsa;

    if ( ! WSAStartup( MAKEWORD( 2, 2 ), &wsa ) ) 
    {
        return TRUE;
    }

    return FALSE;
}

static int set_nonblocking( SOCKET sockfd ) 
{
    u_long mode = 1;

    if ( ioctlsocket(sockfd, FIONBIO, &mode) != NO_ERROR ) 
    {
        return FALSE;
    }

    return TRUE;
}

int icmp_output( const char *buf, int len, ikcpcb *kcp, PICMP icmp )
{
    PICMP_HEADER Header = { 0 };
    void*        Data   = NULL;
    int          Info   = len + sizeof( ICMP_HEADER );

    if ( ( Data = malloc( Info ) ) == NULL )
    {
        return 0;
    }

    memcpy( Data + sizeof( ICMP_HEADER ), buf, len );
    
    Header           = Data;
    Header->type     = 0x08;
    Header->code     = 0x00;
    Header->id       = icmp->id;
    Header->seq      = icmp->seq++;
    Header->checksum = checksum( Data, Info );
    
    Info = sendto( icmp->sock, Data, Info, 0, &icmp->dest, sizeof( icmp->dest ) ); free( Data );

    return Info;
}

PICMP icmp_init( char *host )
{
    PICMP icmp = NULL;

    if ( ! initialize_winsock() )
    {
        return NULL;
    }
    
    if ( ( icmp = malloc( sizeof( ICMP ) ) ) == NULL )
    {
        return NULL;
    }

    memset( icmp, 0, sizeof( ICMP ) );

    icmp->sock                 = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    icmp->dest.sin_family      = AF_INET;
    icmp->dest.sin_port        = htons( 0 );
    icmp->dest.sin_addr.s_addr = inet_addr( host );
    icmp->id                   = GetCurrentProcessId();
    icmp->ikcp                 = ikcp_create( icmp->id, icmp );
    icmp->ikcp->output         = icmp_output;
    icmp->seq                  = 0;

    if ( icmp->sock == INVALID_SOCKET )
    {
        icmp_free( icmp ); return NULL;
    }

    if ( ! set_nonblocking( icmp->sock ) )
    {
        icmp_free( icmp ); return NULL;
    }
    
    ikcp_wndsize( icmp->ikcp, 128, 128 );
    ikcp_nodelay( icmp->ikcp, 0, 10, 0, 0 );

    return icmp;
}

int icmp_send( PICMP icmp, unsigned char *buf, int len )
{
    ikcp_update( icmp->ikcp, GetTickCount() );

    if ( ikcp_send( icmp->ikcp, buf, len ) < 0 )
    {
        return FALSE;
    }

    ikcp_flush( icmp->ikcp );

    return TRUE;
}

int icmp_recv( PICMP icmp, unsigned char *buf, int len )
{
    PIP_HEADER   header_ip    = NULL;
    PICMP_HEADER header_icmp  = NULL;
    char         data[ 1500 ] = { 0 };
    int          size         = 0;
    void*        text         = NULL;

    while ( TRUE )
    {
        ikcp_update( icmp->ikcp, GetTickCount() );

        if ( ( size = recvfrom( icmp->sock, data, sizeof( data ), 0, NULL, NULL ) ) < 0 )
        {
            if ( WSAEWOULDBLOCK != WSAGetLastError() )
            {
                break;
            }
        }

        if ( size <= 0 )
        {
            Sleep( 10 ); continue;
        }

        header_ip   = C_PTR( data );
        header_icmp = C_PTR( data )          + ( header_ip->ihl * 4 );
        text        = C_PTR( header_icmp )   + sizeof( ICMP_HEADER );
        size       -= ( header_ip->ihl * 4 ) + sizeof( ICMP_HEADER );

        if ( header_icmp->id != icmp->id )
        {
            continue;
        }

        if ( ! size || ikcp_input( icmp->ikcp, text, size ) < 0 )
        {
            break;
        }

        if ( ikcp_recv( icmp->ikcp, buf, ikcp_peeksize( icmp->ikcp ) ) > 0 )
        {
            break;
        }

        memset( buf, 0, sizeof( buf ) );
    }

    return size;
}

void icmp_free( PICMP icmp )
{
    /* closed socket handle */
    closesocket( icmp->sock );

    /* free ikcp */
    ikcp_release( icmp->ikcp );

    /* free icmp struct */
    free( icmp );

    /* cleanup winsock */
    WSACleanup();
}
