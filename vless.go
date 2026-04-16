package patcher

import (
	"fmt"
	"net/url"
	"strconv"
)

type VlessConfig struct {
	ServerName  string
	Addr        string
	Port        int
	UUID        string
	Encryption  string
	Flow        string
	Security    string
	Network     string
	SNI         string
	RealitySNI  string
	Fingerprint string
	PublicKey   string
	ShortId     string
	SpiderX     string
}

func (m *SubItem) RetrieveVlessConf() error {
	u := m.Parsed
	if u == nil {
		return fmt.Errorf("vless: parsed URL is nil")
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return fmt.Errorf("vless: missing port in URL")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("vless: invalid port %q: %w", portStr, err)
	}

	uuid := u.User.Username()
	if uuid == "" {
		return fmt.Errorf("vless: missing UUID in URL")
	}

	q := u.Query()
	fragment, _ := url.QueryUnescape(u.Fragment)
	if fragment == "" {
		fragment = u.Fragment
	}

	m.VlessConf = &VlessConfig{
		ServerName:  fragment,
		Addr:        host,
		Port:        port,
		UUID:        uuid,
		Encryption:  q.Get("encryption"),
		Flow:        q.Get("flow"),
		Security:    q.Get("security"),
		Network:     q.Get("type"),
		SNI:         q.Get("sni"),
		RealitySNI:  q.Get("servername"),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortId:     q.Get("sid"),
		SpiderX:     q.Get("spx"),
	}
	return nil
}
