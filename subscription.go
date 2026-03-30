package patcher

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Subscription struct {
	Addr      string
	SubResult Base64Resp
	SubItems  []*SubItem
}

type JSONObject json.RawMessage

type Base64Resp []byte

type SubItem struct {
	Line      []byte
	Parsed    *url.URL
	VmessRaw  JSONObject
	VmessConf *VmessConfig
}

func NewSubscription(addr string) *Subscription {
	return &Subscription{Addr: addr}
}

func (s *Subscription) GetSubscription() error {
	slog.Info(fmt.Sprintf("Sending subscription request: %s", s.Addr))
	resp, err := http.Get(s.Addr)
	if err != nil {
		return err
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	s.SubResult = respBytes
	return nil
}

func (s *Subscription) ParseItems() error {
	if len(s.SubResult) <= 0 {
		return fmt.Errorf("no items in subscription result")
	}
	slog.Info("Parsing subscription result ...")
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(s.SubResult)))
	n, err := base64.StdEncoding.Decode(buf, s.SubResult)
	if err != nil {
		return err
	}
	data := buf[:n]
	scaner := bufio.NewScanner(bytes.NewReader(data))
	scaner.Split(bufio.ScanLines)
	for scaner.Scan() {
		if len(scaner.Bytes()) <= 0 {
			continue
		}
		item := &SubItem{
			Line: scaner.Bytes(),
		}
		err = item.parseItem()
		if err != nil {
			return err
		}
		s.SubItems = append(s.SubItems, item)
	}
	slog.Info(fmt.Sprintf("Finished parsing subscription result: got %d subscription items", len(s.SubItems)))
	return nil
}

func (m *SubItem) ID() string {
	switch {
	case m.VmessRaw != nil:
		return m.VmessConf.Addr + ":" + strconv.Itoa(m.VmessConf.Port)
	}
	return string(m.Line)
}

func (m *SubItem) parseItem() error {
	u, err := url.Parse(string(m.Line))
	if err != nil {
		return err
	}
	m.Parsed = u
	if strings.EqualFold(m.Parsed.Scheme, "vmess") {
		// vmess://
		vmessPayload := m.Line[5+3:]
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(vmessPayload)))
		n, err := base64.StdEncoding.Decode(buf, vmessPayload)
		if err != nil {
			return err
		}
		m.VmessRaw = buf[:n]
		err = m.RetrieveVmessConf()
		if err != nil {
			return err
		}
	}

	return nil
}

// CollectServerAddresses 从订阅中收集所有服务器地址，区分域名和 IP
func (s *Subscription) CollectServerAddresses() (domains []string, ips []string) {
	domainSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})

	for _, item := range s.SubItems {
		if item.VmessConf == nil {
			continue
		}
		addr := item.VmessConf.Addr
		if len(addr) == 0 {
			continue
		}

		// 判断是否为 IP
		if net.ParseIP(addr) != nil {
			ipSet[addr] = struct{}{}
			continue
		}

		// 是域名，判断是否为子域名
		tldPlus1, err := publicsuffix.EffectiveTLDPlusOne(addr)
		if err != nil {
			slog.Warn(fmt.Sprintf("invalid domain found: %s", addr))
			continue
		}

		if tldPlus1 == addr {
			// 顶级域名+1，使用 domain: 前缀
			domainSet["domain:"+addr] = struct{}{}
		} else {
			// 子域名，使用 full: 前缀
			domainSet["full:"+addr] = struct{}{}
		}
	}

	// 转换为切片
	domains = make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	ips = make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return domains, ips
}

// FormatDomainWithPrefix 根据域名是否为子域名，生成 "domain:xxx" 或 "full:xxx" 格式
func FormatDomainWithPrefix(addr string) string {
	if net.ParseIP(addr) != nil {
		return addr
	}
	tldPlus1, err := publicsuffix.EffectiveTLDPlusOne(addr)
	if err != nil {
		return "domain:" + addr
	}
	if tldPlus1 == addr {
		return "domain:" + addr
	}
	return "full:" + addr
}
