package command

import (
	"flag"
	"fmt"
	"github.com/esrrhs/gohome/geoip"
	"net"
	"net/http"
	"proxy2icmp/client"
	"proxy2icmp/icmphandler"
	"proxy2icmp/logger"
	"proxy2icmp/server"
	"proxy2icmp/usage"
	"strconv"
	"time"
)

const AppVersion = "v1.1.2"

func CommandParcer() {
	v := flag.Bool("version", false, "app versiov")
	t := flag.String("type", "", "client or server")
	listen := flag.String("l", "", "listen addr")
	target := flag.String("t", "", "target addr")
	serverFlag := flag.String("s", "", "server addr")
	timeout := flag.Int("timeout", 60, "conn timeout")
	key := flag.Int("key", 0, "key")
	tcpmode := flag.Int("tcp", 0, "tcp mode")
	tcpmode_buffersize := flag.Int("tcp_bs", 1*1024*1024, "tcp mode buffer size")
	tcpmode_maxwin := flag.Int("tcp_mw", 20000, "tcp mode max win")
	tcpmode_resend_timems := flag.Int("tcp_rst", 400, "tcp mode resend time ms")
	tcpmode_compress := flag.Int("tcp_gz", 0, "tcp data compress")
	tcpmode_stat := flag.Int("tcp_stat", 0, "print tcp stat")
	open_sock5 := flag.Int("socks5", 0, "sock5 mode")
	maxconn := flag.Int("maxconn", 0, "max num of connections")
	max_process_thread := flag.Int("maxprt", 100, "max process thread in server")
	max_process_buffer := flag.Int("maxprb", 1000, "max process thread's buffer in server")
	profile := flag.Int("profile", 0, "open profile")
	conntt := flag.Int("conntt", 1000, "the connect call's timeout")
	s5filter := flag.String("s5filter", "", "sock5 filter")
	s5ftfile := flag.String("s5ftfile", "GeoLite2-Country.mmdb", "sock5 filter file")
	encryption := flag.Bool("encryption", false, "encryp icmp msg between client and server")
	logWriter := flag.Int("log", 0, "write log to stdout=0|file=1|devNull=2")
	flag.Usage = func() {
		fmt.Printf(usage.Usage)
	}

	flag.Parse()
	logger.InitLogger(*logWriter)

	if *v {
		fmt.Println("proxy2icmp", AppVersion)
		return
	}

	if *t != "client" && *t != "server" {
		flag.Usage()
		return
	}
	if *t == "client" {
		if len(*listen) == 0 || len(*serverFlag) == 0 {
			flag.Usage()
			return
		}
		if *open_sock5 == 0 && len(*target) == 0 {
			flag.Usage()
			return
		}
		if *open_sock5 != 0 {
			*tcpmode = 1
		}
	}
	if *tcpmode_maxwin*10 > icmphandler.FRAME_MAX_ID {
		fmt.Println("set tcp win to big, max = " + strconv.Itoa(icmphandler.FRAME_MAX_ID/10))
		return
	}

	fmt.Println("proxy2icmp starting ...")
	logger.InfoLogger.Printf("key %d\n", *key)
	if *t == "server" {
		s, err := server.NewServer(*key, *maxconn, *max_process_thread, *max_process_buffer, *conntt, *encryption)
		if err != nil {
			logger.ErrorLogger.Printf("ERROR: %s\n", err.Error())
			return
		}
		logger.InfoLogger.Println("Server start")
		err = s.Run()
		if err != nil {
			logger.ErrorLogger.Printf("Run ERROR: %s\n", err.Error())
			return
		}
	} else if *t == "client" {

		logger.InfoLogger.Printf("type %s\n", *t)
		logger.InfoLogger.Printf("listen %s\n", *listen)
		logger.InfoLogger.Printf("server %s\n", *serverFlag)
		logger.InfoLogger.Printf("target %s\n", *target)

		if *tcpmode == 0 {
			*tcpmode_buffersize = 0
			*tcpmode_maxwin = 0
			*tcpmode_resend_timems = 0
			*tcpmode_compress = 0
			*tcpmode_stat = 0
		}

		if len(*s5filter) > 0 {
			err := geoip.Load(*s5ftfile)
			if err != nil {
				logger.ErrorLogger.Printf("Load Sock5 ip file ERROR: %s\n", err.Error())
				return
			}
		}
		filter := func(addr string) bool {
			if len(*s5filter) <= 0 {
				return true
			}

			taddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return false
			}

			ret, err := geoip.GetCountryIsoCode(taddr.IP.String())
			if err != nil {
				return false
			}
			if len(ret) <= 0 {
				return false
			}
			return ret != *s5filter
		}

		c, err := client.NewClient(*listen, *serverFlag, *target, *timeout, *key,
			*tcpmode, *tcpmode_buffersize, *tcpmode_maxwin, *tcpmode_resend_timems, *tcpmode_compress,
			*tcpmode_stat, *open_sock5, *maxconn, &filter, *encryption)
		if err != nil {
			logger.ErrorLogger.Printf("ERROR: %s\n", err.Error())
			return
		}
		logger.InfoLogger.Printf("Client Listen %s (%s) Server %s (%s) TargetPort %s:\n", c.Addr(), c.IPAddr(),
			c.ServerAddr(), c.ServerIPAddr(), c.TargetAddr())
		err = c.Run()
		if err != nil {
			logger.ErrorLogger.Printf("Run ERROR: %s\n", err.Error())
			return
		}
	} else {
		return
	}

	if *profile > 0 {
		go http.ListenAndServe("0.0.0.0:"+strconv.Itoa(*profile), nil)
	}

	for {
		time.Sleep(time.Hour)
	}
}
