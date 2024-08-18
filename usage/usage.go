package usage

var Usage = `
    By forging ping, the tcp/udp/sock5 traffic is forwarded to the destination server through the remote server. Used to break certain operators to block TCP/UDP traffic.

Usage:

    // server
    pingtunnel -type server

    // client, Forward udp
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -t SERVER_IP:4455

    // client, Forward tcp
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -t SERVER_IP:4455 -tcp 1

    // client, Forward sock5, implicitly open tcp, so no target server is needed
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -sock5 1

    -type     
              client or server
    -encryption
              encrypt icmp messages (default is off)    
    -version
              app version           
server param:

    -key      
              Set password, default 0

    -nolog    
              Do not write log files, only print standard output, default 0 is off

    -noprint  
              Do not print standard output, default 0 is off

    -maxconn  
              the max num of connections, default 0 is no limit

    -maxprt  
              max process thread in server, default 100

    -maxprb   
              max process thread's buffer in server, default 1000

    -conntt   
              The timeout period for the server to initiate a connection to the destination address. The default is 1000ms.

client param:

    -l        
              Local address, traffic sent to this port will be forwarded to the server

    -s        
              The address of the server, the traffic will be forwarded to this server through the tunnel

    -t        
              Destination address forwarded by the remote server, traffic will be forwarded to this address

    -timeout  
              The time when the local record connection timed out, in seconds, 60 seconds by default

    -key      
              Set password, default 0

    -tcp      
              Set the switch to forward tcp, the default is 0

    -tcp_bs   
              Tcp send and receive buffer size, default 1MB

    -tcp_mw   
              The maximum window of tcp, the default is 20000

    -tcp_rst  
              Tcp timeout resend time, default 400ms

    -tcp_gz   
              Tcp will compress data when the packet exceeds this size, 0 means no compression, default 0

    -tcp_stat 
              Print tcp connection statistic, default 0 is off

    -log    
              Write log to stdout=0|file=1|devNull=2, default 0 is stdout

    -noprint  
              Do not print standard output, default 0 is off

    -socks5    
              Turn on sock5 forwarding, default 0 is off

    -profile  
              Enable performance detection on the specified port. The default 0 is not enabled.

    -s5filter 
              Set the forwarding filter in the sock5 mode. The default is full forwarding. For example, setting the CN indicates that the Chinese address is not forwarded.

    -s5ftfile 
              The data file in sock5 filter mode, the default reading of the current directory GeoLite2-Country.mmdb
`
