from kcp import KCP
import time
import sys
import struct
import socket
import threading

def exception_capture( func, *args, **kwargs ):
    def wrapper( *args, **kwargs ):
        try:
            return func( *args, **kwargs )
        except Exception as e:
            print( e )
    return wrapper

def refresh_display_row( text : str ):
    sys.stdout.write( '\r\033[K' + text + '\n' )
    sys.stdout.write( '> ' )
    sys.stdout.flush()

def checksum( data ):
    s = 0

    for i in range( 0, len( data ), 2 ):
        a = data[ i ]
        b = data[ i + 1 ] if i + 1 < len( data ) else 0
        s = s + ( a + ( b << 8 ) )

    s = ( s >> 16 ) + ( s & 0xffff )
    s = s + ( s >> 16 )

    return ~s & 0xffff

def icmp_output( kcp : KCP, data : bytes ):
    server   : socket.socket = kcp.user_data[ 'sock' ]
    options  : dict          = kcp.user_data
    header   : bytes         = bytes()
    check    : int           = 0

    header = struct.pack( 'BBHHH', 0, 0, check, options[ 'id' ], options[ 'seq' ] )
    check  = checksum( header + data )
    header = struct.pack( 'BBHHH', 0, 0, check, options[ 'id' ], options[ 'seq' ] )

    server.sendto( header + data, options[ 'addr' ] )

def icmp_parser( data : bytes ) -> dict:
    options = { }
    data    = data[ 20 : ] # skip first 20 bytes (tcp/ip header)

    options[ 'type' ]     = struct.unpack( 'B', data[ 0 : 1 ] )[ 0 ]
    options[ 'code' ]     = struct.unpack( 'B', data[ 1 : 2 ] )[ 0 ]
    options[ 'checksum' ] = struct.unpack( 'H', data[ 2 : 4 ] )[ 0 ]
    options[ 'id' ]       = struct.unpack( 'H', data[ 4 : 6 ] )[ 0 ]
    options[ 'seq' ]      = struct.unpack( 'H', data[ 6 : 8 ] )[ 0 ]
    options[ 'data' ]     = data[ 8 : ]

    return options

def record( clients : dict, options : dict ):
    if options[ 'id' ] not in clients:
        kcp = KCP( conv = options[ 'id' ], output = icmp_output, user_data = options )

        kcp.set_wndsize( 128, 128 )
        kcp.set_nodelay( None, 10, 0, False )
        kcp.update( int( time.time() * 1000 ) )

        clients[ options[ 'id' ] ] = kcp

        refresh_display_row( '[+] new client [' + str( options[ 'id' ] ) + '] connected.' )

    kcp : KCP = clients[ options[ 'id' ] ]

    kcp.update( int( time.time() * 1000 ) )
    kcp.input( options[ 'data' ] )

    if kcp.peeksize() > 0:
        refresh_display_row( '[+] received from [' + str( options[ 'id' ] ) + ']: ' + kcp.recv().decode() )

def send_from_id( clients : dict ):
    tokens = input( '> ' ).split( ' ' )

    if len( tokens ) < 2:
        raise ValueError( 'Invalid command' )
    
    id   = int( tokens[ 0 ] )
    text = ' '.join( tokens[ 1 : ] )

    if id not in clients:
        raise ValueError( 'Invalid id' )

    kcp = clients[ id ]
    kcp.update( int( time.time() * 1000 ) )
    kcp.send( text.encode() )
    kcp.flush()

    print( "[>] sent to [" + str( id ) + "]: " + text )

def input_thread( clients : dict ):
    while True:
        send_from_id( clients )

@exception_capture
def main():
    clients = { }
    server  = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP )
    server.bind( ( '0.0.0.0', 0 ) )

    print( 'Icmp Listening...' )

    threading.Thread( target = input_thread, args = ( clients, ) ).start()

    while True:
        data, addr        = server.recvfrom( 1500 )
        options           = icmp_parser( data )
        options[ 'addr' ] = addr
        options[ 'sock' ] = server

        record( clients, options )

if __name__ == '__main__':
    main()
