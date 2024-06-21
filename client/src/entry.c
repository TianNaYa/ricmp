#include <icmp.h>

void entry( void )
{
    PICMP icmp         = NULL;
    char  data[ 1024 ] = { 0 };

    printf( "Pid: %d\n", GetCurrentProcessId() );

    if ( ( icmp = icmp_init( "192.168.49.130" ) ) == NULL )
    {
        printf( "icmp_init failed\n" );
        return;
    }

    icmp_send( icmp, "hello", 6 );

    icmp_recv( icmp, data, sizeof( data ) );

    printf( "Recv: %s\n", data );

    icmp_free( icmp );
}
