package server

import (
	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/frame"
	"github.com/esrrhs/gohome/threadpool"
	"github.com/golang/protobuf/proto"
	
	// "github.com/esrrhs/gohome/loggo"
	// "google.golang.org/golang/protobuf/proto"
	"net"
	"proxy2icmp/icmphandler"
	"proxy2icmp/logger"
	"proxy2icmp/msg"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

func NewServer(key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connecttmeout int,encryption bool) (*Server, error) {
	s := &Server{
		exit:             false,
		key:              key,
		maxconn:          maxconn,
		maxprocessthread: maxprocessthread,
		maxprocessbuffer: maxprocessbuffer,
		connecttmeout:    connecttmeout,
		encryptEnable:             encryption,
	}

	if maxprocessthread > 0 {
		s.processtp = threadpool.NewThreadPool(maxprocessthread, maxprocessbuffer, func(v interface{}) {
			packet := v.(*icmphandler.Packet)
			s.processDataPacket(packet)
		})
	}

	return s, nil
}

type Server struct {
	exit             bool
	key              int
	workResultLock   sync.WaitGroup
	maxconn          int
	maxprocessthread int
	maxprocessbuffer int
	connecttmeout    int

	conn *icmp.PacketConn

	localConnMap sync.Map
	connErrorMap sync.Map

	sendPacket       uint64
	recvPacket       uint64
	sendPacketSize   uint64
	recvPacketSize   uint64
	localConnMapSize int

	processtp   *threadpool.ThreadPool
	recvcontrol chan int
	encryptEnable bool
}

type ServerConn struct {
	exit           bool
	timeout        int
	ipaddrTarget   *net.UDPAddr
	conn           *net.UDPConn
	tcpaddrTarget  *net.TCPAddr
	tcpconn        *net.TCPConn
	id             string
	activeRecvTime time.Time
	activeSendTime time.Time
	close          bool
	rproto         int
	fm             *frame.FrameMgr
	tcpmode        int
	EchoId         int
	EchoSeq        int
}

func (p *Server) Run() error {

	conn, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		logger.ErrorLogger.Printf("Error listening for ICMP packets: %s\n", err.Error())
		return err
	}
	p.conn = conn

	recv := make(chan *icmphandler.Packet, 10000)
	p.recvcontrol = make(chan int, 1)
	go icmphandler.RecvICMP(&p.workResultLock, &p.exit, *p.conn, recv,p.encryptEnable)

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			p.checkTimeoutConn()
			p.showNet()
			p.updateConnError()
			time.Sleep(time.Second)
		}
	}()

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			select {
			case <-p.recvcontrol:
				return
			case r := <-recv:
				p.processPacket(r)
			}
		}
	}()

	return nil
}

func (p *Server) Stop() {
	p.exit = true
	p.recvcontrol <- 1
	p.workResultLock.Wait()
	p.processtp.Stop()
	p.conn.Close()
}

func (p *Server) processPacket(packet *icmphandler.Packet) {

	if packet.My.Key != (int32)(p.key) {
		return
	}

	if packet.My.Type == (int32)(msg.MyMsg_PING) {
		t := time.Time{}
		t.UnmarshalBinary(packet.My.Data)
		// logger.InfoLogger.Printf("ping from %s %s %d %d %d\n", packet.Src.String(), t.String(), packet.My.Rproto, packet.EchoId, packet.EchoSeq)
		icmphandler.SendICMP(packet.EchoId, packet.EchoSeq, *p.conn, packet.Src, "", "", (uint32)(msg.MyMsg_PING), packet.My.Data,
			(int)(packet.My.Rproto), -1, p.key,
			0, 0, 0, 0, 0, 0,
			0,p.encryptEnable)
		return
	}

	if packet.My.Type == (int32)(msg.MyMsg_KICK) {
		localConn := p.getServerConnById(packet.My.Id)
		if localConn != nil {
			p.close(localConn)
			logger.InfoLogger.Printf("remote kick local %s\n", packet.My.Id)
		}
		return
	}

	if p.maxprocessthread > 0 {
		p.processtp.AddJob((int)(common.HashString(packet.My.Id)), packet)
	} else {
		p.processDataPacket(packet)
	}
}

func (p *Server) processDataPacketNewConn(id string, packet *icmphandler.Packet) *ServerConn {

	now := common.GetNowUpdateInSecond()

	logger.InfoLogger.Printf("start add new connect  %s %s\n", id, packet.My.Target)

	if p.maxconn > 0 && p.localConnMapSize >= p.maxconn {
		logger.InfoLogger.Printf("too many connections %d, server connected target fail %s\n", p.localConnMapSize, packet.My.Target)
		p.remoteError(packet.EchoId, packet.EchoSeq, id, (int)(packet.My.Rproto), packet.Src)
		return nil
	}

	addr := packet.My.Target
	if p.isConnError(addr) {
		logger.InfoLogger.Printf("addr connect Error before: %s %s\n", id, addr)
		p.remoteError(packet.EchoId, packet.EchoSeq, id, (int)(packet.My.Rproto), packet.Src)
		return nil
	}

	if packet.My.Tcpmode > 0 {

		c, err := net.DialTimeout("tcp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		if err != nil {
			logger.ErrorLogger.Printf("Error listening for tcp packets: %s %s\n", id, err.Error())
			p.remoteError(packet.EchoId, packet.EchoSeq, id, (int)(packet.My.Rproto), packet.Src)
			p.addConnError(addr)
			return nil
		}
		targetConn := c.(*net.TCPConn)
		ipaddrTarget := targetConn.RemoteAddr().(*net.TCPAddr)

		fm := frame.NewFrameMgr(icmphandler.FRAME_MAX_SIZE, icmphandler.FRAME_MAX_ID, (int)(packet.My.TcpmodeBuffersize), (int)(packet.My.TcpmodeMaxwin), (int)(packet.My.TcpmodeResendTimems), (int)(packet.My.TcpmodeCompress),
			(int)(packet.My.TcpmodeStat))

		localConn := &ServerConn{exit: false, timeout: (int)(packet.My.Timeout), tcpconn: targetConn, tcpaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.My.Rproto), fm: fm, tcpmode: (int)(packet.My.Tcpmode)}

		p.addServerConn(id, localConn)

		go p.RecvTCP(localConn, id, packet.Src)
		return localConn

	} else {

		c, err := net.DialTimeout("udp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		if err != nil {
			logger.ErrorLogger.Printf("Error listening for udp packets: %s %s\n", id, err.Error())
			p.remoteError(packet.EchoId, packet.EchoSeq, id, (int)(packet.My.Rproto), packet.Src)
			p.addConnError(addr)
			return nil
		}
		targetConn := c.(*net.UDPConn)
		ipaddrTarget := targetConn.RemoteAddr().(*net.UDPAddr)

		localConn := &ServerConn{exit: false, timeout: (int)(packet.My.Timeout), conn: targetConn, ipaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.My.Rproto), tcpmode: (int)(packet.My.Tcpmode)}

		p.addServerConn(id, localConn)

		go p.Recv(localConn, id, packet.Src)

		return localConn
	}
}

func (p *Server) processDataPacket(packet *icmphandler.Packet) {

	// logger.InfoLogger.Printf("processPacket %s %s %d\n", packet.My.Id, packet.Src.String(), len(packet.My.Data))

	now := common.GetNowUpdateInSecond()

	id := packet.My.Id
	localConn := p.getServerConnById(id)
	if localConn == nil {
		localConn = p.processDataPacketNewConn(id, packet)
		if localConn == nil {
			return
		}
	}

	localConn.activeRecvTime = now
	localConn.EchoId = packet.EchoId
	localConn.EchoSeq = packet.EchoSeq

	if packet.My.Type == (int32)(msg.MyMsg_DATA) {

		if packet.My.Tcpmode > 0 {
			f := &frame.Frame{}
			err := proto.Unmarshal(packet.My.Data, f)
			if err != nil {
				logger.ErrorLogger.Printf("Unmarshal tcp Error %s\n", err)
				return
			}

			localConn.fm.OnRecvFrame(f)

		} else {
			if packet.My.Data == nil {
				return
			}
			if localConn.conn==nil{
				return
			}
			_, err := localConn.conn.Write(packet.My.Data)
			if err != nil {
				logger.InfoLogger.Printf("WriteToUDP Error %s\n", err)
				localConn.close = true
				return
			}
		}

		p.recvPacket++
		p.recvPacketSize += (uint64)(len(packet.My.Data))
	}
}

func (p *Server) RecvTCP(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	logger.InfoLogger.Printf("server waiting target response %s -> %s %s\n", conn.tcpaddrTarget.String(), conn.id, conn.tcpconn.LocalAddr().String())

	logger.InfoLogger.Printf("start wait remote connect tcp %s %s\n", conn.id, conn.tcpaddrTarget.String())
	startConnectTime := common.GetNowUpdateInSecond()
	for !p.exit && !conn.exit {
		if conn.fm.IsConnected() {
			break
		}
		conn.fm.Update()
		sendlist := conn.fm.GetSendList()
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*frame.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			icmphandler.SendICMP(conn.EchoId, conn.EchoSeq, *p.conn, src, "", id, (uint32)(msg.MyMsg_DATA), mb,
				conn.rproto, -1, p.key,
				0, 0, 0, 0, 0, 0,
				0,p.encryptEnable)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}
		time.Sleep(time.Millisecond * 10)
		now := common.GetNowUpdateInSecond()
		diffclose := now.Sub(startConnectTime)
		if diffclose > time.Second*5 {
			logger.InfoLogger.Printf("can not connect remote tcp %s %s\n", conn.id, conn.tcpaddrTarget.String())
			p.close(conn)
			p.remoteError(conn.EchoId, conn.EchoSeq, id, conn.rproto, src)
			return
		}
	}

	if !conn.exit {
		logger.InfoLogger.Printf("remote connected tcp %s %s\n", conn.id, conn.tcpaddrTarget.String())
	}

	bytes := make([]byte, 10240)

	tcpActiveRecvTime := common.GetNowUpdateInSecond()
	tcpActiveSendTime := common.GetNowUpdateInSecond()

	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()
		sleep := true

		left := common.MinOfInt(conn.fm.GetSendBufferLeft(), len(bytes))
		if left > 0 {
			conn.tcpconn.SetReadDeadline(time.Now().Add(time.Millisecond * 1))
			n, err := conn.tcpconn.Read(bytes[0:left])
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					logger.ErrorLogger.Printf("Error read tcp %s %s %s\n", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break
				}
			}
			if n > 0 {
				sleep = false
				conn.fm.WriteSendBuffer(bytes[:n])
				tcpActiveRecvTime = now
			}
		}

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		if sendlist.Len() > 0 {
			sleep = false
			conn.activeSendTime = now
			for e := sendlist.Front(); e != nil; e = e.Next() {
				f := e.Value.(*frame.Frame)
				mb, err := conn.fm.MarshalFrame(f)
				if err != nil {
					logger.ErrorLogger.Printf("Error tcp Marshal %s %s %s\n", conn.id, conn.tcpaddrTarget.String(), err)
					continue
				}
				icmphandler.SendICMP(conn.EchoId, conn.EchoSeq, *p.conn, src, "", id, (uint32)(msg.MyMsg_DATA), mb,
					conn.rproto, -1, p.key,
					0, 0, 0, 0, 0, 0,
					0,p.encryptEnable)
				p.sendPacket++
				p.sendPacketSize += (uint64)(len(mb))
			}
		}

		if conn.fm.GetRecvBufferSize() > 0 {
			sleep = false
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 1))
			n, err := conn.tcpconn.Write(rr)
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					logger.ErrorLogger.Printf("Error write tcp %s %s %s\n", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break
				}
			}
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				tcpActiveSendTime = now
			}
		}

		if sleep {
			time.Sleep(time.Millisecond * 10)
		}

		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		tcpdiffrecv := now.Sub(tcpActiveRecvTime)
		tcpdiffsend := now.Sub(tcpActiveSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) ||
			(tcpdiffrecv > time.Second*(time.Duration(conn.timeout)) && tcpdiffsend > time.Second*(time.Duration(conn.timeout))) {
			logger.InfoLogger.Printf("close inactive conn %s %s\n", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}

		if conn.fm.IsRemoteClosed() {
			logger.InfoLogger.Printf("closed by remote conn %s %s\n", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}
	}

	conn.fm.Close()

	startCloseTime := common.GetNowUpdateInSecond()
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*frame.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			icmphandler.SendICMP(conn.EchoId, conn.EchoSeq, *p.conn, src, "", id, (uint32)(msg.MyMsg_DATA), mb,
				conn.rproto, -1, p.key,
				0, 0, 0, 0, 0, 0,
				0,p.encryptEnable)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}

		nodatarecv := true
		if conn.fm.GetRecvBufferSize() > 0 {
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			n, _ := conn.tcpconn.Write(rr)
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				nodatarecv = false
			}
		}

		diffclose := now.Sub(startCloseTime)
		if diffclose > time.Second*60 {
			logger.InfoLogger.Printf("close conn had timeout %s %s\n", conn.id, conn.tcpaddrTarget.String())
			break
		}

		remoteclosed := conn.fm.IsRemoteClosed()
		if remoteclosed && nodatarecv {
			logger.InfoLogger.Printf("remote conn had closed %s %s\n", conn.id, conn.tcpaddrTarget.String())
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second)

	logger.InfoLogger.Printf("close tcp conn %s %s\n", conn.id, conn.tcpaddrTarget.String())
	p.close(conn)
}

func (p *Server) Recv(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	logger.InfoLogger.Printf("server waiting target response %s -> %s %s\n", conn.ipaddrTarget.String(), conn.id, conn.conn.LocalAddr().String())

	bytes := make([]byte, 2000)

	for !p.exit {

		conn.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, _, err := conn.conn.ReadFromUDP(bytes)
		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				logger.ErrorLogger.Printf("ReadFromUDP Error read udp %s\n", err)
				conn.close = true
				return
			}
		}

		now := common.GetNowUpdateInSecond()
		conn.activeSendTime = now

		icmphandler.SendICMP(conn.EchoId, conn.EchoSeq, *p.conn, src, "", id, (uint32)(msg.MyMsg_DATA), bytes[:n],
			conn.rproto, -1, p.key,
			0, 0, 0, 0, 0, 0,
			0,p.encryptEnable)

		p.sendPacket++
		p.sendPacketSize += (uint64)(n)
	}
}

func (p *Server) close(conn *ServerConn) {
	if p.getServerConnById(conn.id) != nil {
		conn.exit = true
		if conn.conn != nil {
			conn.conn.Close()
		}
		if conn.tcpconn != nil {
			conn.tcpconn.Close()
		}
		p.deleteServerConn(conn.id)
	}
}

func (p *Server) checkTimeoutConn() {

	tmp := make(map[string]*ServerConn)
	p.localConnMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		serverConn := value.(*ServerConn)
		tmp[id] = serverConn
		return true
	})

	now := common.GetNowUpdateInSecond()
	for _, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) {
			conn.close = true
		}
	}

	for id, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		if conn.close {
			logger.InfoLogger.Printf("close inactive conn %s %s\n", id, conn.ipaddrTarget.String())
			p.close(conn)
		}
	}
}

func (p *Server) showNet() {
	p.localConnMapSize = 0
	p.localConnMap.Range(func(key, value interface{}) bool {
		p.localConnMapSize++
		return true
	})
	// fmt.Print("\033[H\033[2J")
	logger.InfoLogger.Printf("send %dPacket/s %dKB/s recv %dPacket/s %dKB/s %dConnections\n",
		p.sendPacket, p.sendPacketSize/1024, p.recvPacket, p.recvPacketSize/1024, p.localConnMapSize)
	p.sendPacket = 0
	p.recvPacket = 0
	p.sendPacketSize = 0
	p.recvPacketSize = 0
}

func (p *Server) addServerConn(uuid string, serverConn *ServerConn) {
	p.localConnMap.Store(uuid, serverConn)
}

func (p *Server) getServerConnById(uuid string) *ServerConn {
	ret, ok := p.localConnMap.Load(uuid)
	if !ok {
		return nil
	}
	return ret.(*ServerConn)
}

func (p *Server) deleteServerConn(uuid string) {
	p.localConnMap.Delete(uuid)
}

func (p *Server) remoteError(EchoId int, EchoSeq int, uuid string, rprpto int, src *net.IPAddr) {
	icmphandler.SendICMP(EchoId, EchoSeq, *p.conn, src, "", uuid, (uint32)(msg.MyMsg_KICK), []byte{},
		rprpto, -1, p.key,
		0, 0, 0, 0, 0, 0,
		0,p.encryptEnable)
}

func (p *Server) addConnError(addr string) {
	_, ok := p.connErrorMap.Load(addr)
	if !ok {
		now := common.GetNowUpdateInSecond()
		p.connErrorMap.Store(addr, now)
	}
}

func (p *Server) isConnError(addr string) bool {
	_, ok := p.connErrorMap.Load(addr)
	return ok
}

func (p *Server) updateConnError() {

	tmp := make(map[string]time.Time)
	p.connErrorMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		t := value.(time.Time)
		tmp[id] = t
		return true
	})

	now := common.GetNowUpdateInSecond()
	for id, t := range tmp {
		diff := now.Sub(t)
		if diff > time.Second*5 {
			p.connErrorMap.Delete(id)
		}
	}
}