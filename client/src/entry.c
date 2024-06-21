#include <icmp.h>

void entry( void )
{
    PICMP icmp         = NULL;
    char  data[ 2000 ] = { 0 };

    printf( "Pid: %d\n", GetCurrentProcessId() );

    if ( ( icmp = icmp_init( "192.168.49.130" ) ) == NULL )
    {
        printf( "icmp_init failed\n" );
        return;
    }

    while ( TRUE )
    {
        icmp_send( icmp, data, sprintf( data, "hello %d", GetCurrentProcessId() ) );

        memset( data, 0, sizeof( data ) );

        icmp_recv( icmp, data, sizeof( data ) );

        printf( "Recv: %s\n", data );
    }

    icmp_free( icmp );
}
