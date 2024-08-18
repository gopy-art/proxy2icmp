package icmphandler

import (
	"encoding/binary"
	// "fmt"
	"io"

	"github.com/esrrhs/gohome/common"
	// "github.com/esrrhs/gohome/loggo"
	// "github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/runtime/protoiface"

	// "github.com/golang/protobuf/proto"
	"net"
	"proxy2icmp/msg"
	"sync"
	"time"

	"proxy2icmp/logger"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"crypto/aes"
	"crypto/cipher"
	cRand "crypto/rand"
	"crypto/sha256"
	"errors"
	// "encoding/base64"
)

func SendICMP(id int, sequence int, conn icmp.PacketConn, server *net.IPAddr, target string,
	connId string, msgType uint32, data []byte, sproto int, rproto int, key int,
	tcpmode int, tcpmode_buffer_size int, tcpmode_maxwin int, tcpmode_resend_time int, tcpmode_compress int, tcpmode_stat int,
	timeout int, cryptoEnable bool) {

	if cryptoEnable {
		hasher := sha256.New()
		hasher.Write([]byte(connId))
		hash := hasher.Sum(nil)
		data, _ = EncryptMessage(hash, data)
	}
	// fmt.Println("--> sending icmp data :",string(data))

	m := &msg.MyMsg{
		Id:                  connId,
		Type:                (int32)(msgType),
		Target:              target,
		Data:                data,
		Rproto:              (int32)(rproto),
		Key:                 (int32)(key),
		Tcpmode:             (int32)(tcpmode),
		TcpmodeBuffersize:   (int32)(tcpmode_buffer_size),
		TcpmodeMaxwin:       (int32)(tcpmode_maxwin),
		TcpmodeResendTimems: (int32)(tcpmode_resend_time),
		TcpmodeCompress:     (int32)(tcpmode_compress),
		TcpmodeStat:         (int32)(tcpmode_stat),
		Timeout:             (int32)(timeout),
		Magic:               (int32)(msg.MyMsg_MAGIC),
	}

	mb, err := proto.Marshal(convertMessageV1ToV2(m))
	if err != nil {
		logger.ErrorLogger.Printf("sendICMP Marshal MyMsg error %s %s\n", server.String(), err)
		return
	}

	body := &icmp.Echo{
		ID:   id,
		Seq:  sequence,
		Data: mb,
	}

	msg := &icmp.Message{
		Type: (ipv4.ICMPType)(sproto),
		Code: 0,
		Body: body,
	}

	bytes, err := msg.Marshal(nil)
	if err != nil {
		logger.ErrorLogger.Printf("sendICMP Marshal error %s %s\n", server.String(), err)
		return
	}

	conn.WriteTo(bytes, server)
}

func RecvICMP(workResultLock *sync.WaitGroup, exit *bool, conn icmp.PacketConn, recv chan<- *Packet, cryptoEnable bool) {

	defer common.CrashLog()

	(*workResultLock).Add(1)
	defer (*workResultLock).Done()

	bytes := make([]byte, 10240)
	for !*exit {
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, srcaddr, err := conn.ReadFrom(bytes)

		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				logger.ErrorLogger.Printf("Error read icmp message %s\n", err)
				continue
			}
		}

		if n <= 0 {
			continue
		}

		echoId := int(binary.BigEndian.Uint16(bytes[4:6]))
		echoSeq := int(binary.BigEndian.Uint16(bytes[6:8]))

		my := &msg.MyMsg{}
		err = proto.Unmarshal(bytes[8:n], convertMessageV1ToV2(my))
		if err != nil {
			logger.ErrorLogger.Printf("Unmarshal MyMsg error: %s\n", err)
			continue
		}

		if my.Magic != (int32)(msg.MyMsg_MAGIC) {
			logger.InfoLogger.Printf("processPacket data invalid %s\n", my.Id)
			continue
		}

		// fmt.Println("<-- reciev icmp data :",string(my.Data))
		if cryptoEnable {
			hasher := sha256.New()
			hasher.Write([]byte(my.Id))
			hash := hasher.Sum(nil)
			my.Data, _ = DecryptMessage(hash, my.Data)
		}
		recv <- &Packet{My: my,
			Src:    srcaddr.(*net.IPAddr),
			EchoId: echoId, EchoSeq: echoSeq}
	}
}

type Packet struct {
	My      *msg.MyMsg
	Src     *net.IPAddr
	EchoId  int
	EchoSeq int
}

const (
	FRAME_MAX_SIZE int = 888
	FRAME_MAX_ID   int = 1000000
)

func EncryptMessage(key []byte, byteMsg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(cRand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)
	return cipherText, nil
}

func DecryptMessage(key []byte, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("invalid ciphertext block size")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, nil
}

func convertMessageV1ToV2(v1Message protoiface.MessageV1) proto.Message {
	return protoadapt.MessageV2Of(v1Message)
}
