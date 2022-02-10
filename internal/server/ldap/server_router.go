package ldap

import (
	"github.com/lor00x/goldap/message"
	"github.com/op/go-logging"
	"github.com/vjeantet/ldapserver"
	"log"
)

var _ Handler = (*handler)(nil)

type Handler interface {
	i()

	Bind() ldapserver.HandlerFunc
	Add() ldapserver.HandlerFunc
	Search() ldapserver.HandlerFunc
}

type handler struct {
	logger            *logging.Logger
	payloadAttributes *map[string]string
}

func (h *handler) i() {}

func GenAllRoutes(logger *logging.Logger, payloadAttributes *map[string]string) *ldapserver.RouteMux {
	routes := ldapserver.NewRouteMux()
	routerHelper := &handler{
		logger:            logger,
		payloadAttributes: payloadAttributes,
	}
	routes.Bind(routerHelper.Bind())
	routes.Add(routerHelper.Add())
	routes.Search(routerHelper.Search())
	return routes
}

func (h *handler) Bind() ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetBindRequest()
		h.logger.Infof("ldap request %s for bind:\n%+v", m.Client.Addr().String(), r)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
	}
}

func (h *handler) Add() ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetAddRequest()
		log.Printf("Adding entry: %s", r.Entry())
		//attributes values
		for _, attribute := range r.Attributes() {
			for _, attributeValue := range attribute.Vals() {
				log.Printf("- %s:%s", attribute.Type_(), attributeValue)
			}
		}
		res := ldapserver.NewAddResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
	}
}

func (h *handler) Search() ldapserver.HandlerFunc {
	return func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		r := m.GetSearchRequest()
		h.logger.Infof("Request BaseDn=%s", r.BaseObject())
		h.logger.Infof("Request Filter=%s", r.Filter())
		h.logger.Infof("Request FilterString=%s", r.FilterString())
		h.logger.Infof("Request Attributes=%s", r.Attributes())
		h.logger.Infof("Request TimeLimit=%d", r.TimeLimit().Int())

		// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
		select {
		case <-m.Done:
			h.logger.Infof("Leaving handleSearch...")
			return
		default:
		}

		e := ldapserver.NewSearchResultEntry(string(r.BaseObject()))
		for key := range *h.payloadAttributes {
			h.logger.Debugf("key: %s value:%s", key, (*h.payloadAttributes)[key])
			e.AddAttribute(message.AttributeDescription(key), message.AttributeValue((*h.payloadAttributes)[key]))
		}
		w.Write(e)

		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)

	}
}
