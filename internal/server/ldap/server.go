package ldap

import (
	"fmt"
	"github.com/op/go-logging"
	"github.com/vjeantet/ldapserver"
	"os"
	"os/signal"
	"syscall"
)

type Server struct {
	Host              string
	Port              int
	ds                *ldapserver.Server
	logger            *logging.Logger
	payloadAttributes map[string]string
}

func New(host string, port int, logger *logging.Logger, payloadAttributes map[string]string) *Server {
	return &Server{
		Host:              host,
		Port:              port,
		ds:                ldapserver.NewServer(),
		logger:            logger,
		payloadAttributes: payloadAttributes,
	}
}

func (s *Server) Run() {
	s.ds.Handle(GenAllRoutes(s.logger, &s.payloadAttributes))
	go s.listen()

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	s.Stop()
}

func (s *Server) Stop() {
	s.ds.Stop()
}

func (s *Server) listen() {
	err := s.ds.ListenAndServe(fmt.Sprintf("%s:%d", s.Host, s.Port), func(server *ldapserver.Server) {
		// Called if server is listening successfully
		s.logger.Infof("server listening at %s:%d", s.Host, s.Port)
	})
	if err != nil {
		s.logger.Fatalf("server failed to listen %v", err)
	}
}

func (s *Server) SetPayloadAttributes(payloadAttributes map[string]string) {
	s.payloadAttributes = payloadAttributes
}
