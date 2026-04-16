package patcher

import (
	"fmt"
	"net/url"
	"strconv"
)

type Hysteria2Config struct {
	ServerName string
	Addr       string
	Port       int
	Auth       string
	SNI        string
	Insecure   bool
}

func (m *SubItem) RetrieveHysteria2Conf() error {
	u := m.Parsed
	if u == nil {
		return fmt.Errorf("hysteria2: parsed URL is nil")
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return fmt.Errorf("hysteria2: missing port in URL")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("hysteria2: invalid port %q: %w", portStr, err)
	}

	auth := u.User.Username()
	if auth == "" {
		return fmt.Errorf("hysteria2: missing auth in URL")
	}

	q := u.Query()
	fragment, _ := url.QueryUnescape(u.Fragment)
	if fragment == "" {
		fragment = u.Fragment
	}

	insecure := q.Get("insecure") == "1"

	m.Hysteria2Conf = &Hysteria2Config{
		ServerName: fragment,
		Addr:       host,
		Port:       port,
		Auth:       auth,
		SNI:        q.Get("sni"),
		Insecure:   insecure,
	}
	return nil
}
