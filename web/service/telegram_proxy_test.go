package service

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"github.com/xtls/xray-core/infra/conf"
)

func TestTelegramBridgeRoutesOnlyItsOwnInbound(t *testing.T) {
	cfg := &xray.Config{
		OutboundConfigs: []byte(`[{"tag":"direct","protocol":"freedom"},{"tag":"telegram-egress","protocol":"socks","settings":{"address":"127.0.0.1","port":1080}}]`),
		RouterConfig:    []byte(`{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","network":"tcp","outboundTag":"direct"}]}`),
		InboundConfigs:  []xray.InboundConfig{{Port: 12345, Tag: "existing"}},
	}
	bridge := telegramBridge{port: 23456, account: telegramProxyAccount{User: "bot", Pass: "test-password"}}
	if err := addTelegramBridge(cfg, "missing", bridge); err == nil || len(cfg.InboundConfigs) != 1 {
		t.Fatal("an unavailable outbound must not create a bridge")
	}
	if err := addTelegramBridge(cfg, "telegram-egress", bridge); err != nil {
		t.Fatal(err)
	}
	if len(cfg.InboundConfigs) != 2 {
		t.Fatalf("unexpected inbound count: %d", len(cfg.InboundConfigs))
	}
	inbound := cfg.InboundConfigs[1]
	if string(inbound.Listen) != `"127.0.0.1"` || inbound.Tag != telegramInboundTag || inbound.Protocol != "mixed" || inbound.Port != bridge.port {
		t.Fatalf("unexpected bridge: %+v", inbound)
	}
	var credentials struct {
		Auth     string
		Accounts []telegramProxyAccount
	}
	if err := json.Unmarshal(inbound.Settings, &credentials); err != nil || credentials.Auth != "password" ||
		len(credentials.Accounts) != 1 || credentials.Accounts[0] != bridge.account {
		t.Fatal("bridge does not require the expected credentials")
	}
	var routing struct {
		DomainStrategy string
		Rules          []struct {
			InboundTag  []string
			OutboundTag string
			Network     string
		}
	}
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	if routing.DomainStrategy != "IPIfNonMatch" || len(routing.Rules) != 2 ||
		len(routing.Rules[0].InboundTag) != 1 || routing.Rules[0].InboundTag[0] != telegramInboundTag ||
		routing.Rules[0].OutboundTag != "telegram-egress" || routing.Rules[1].OutboundTag != "direct" || routing.Rules[1].Network != "tcp" {
		t.Fatalf("unexpected routing: %s", cfg.RouterConfig)
	}
	generated, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var parsed conf.Config
	if err := json.Unmarshal(generated, &parsed); err != nil {
		t.Fatal(err)
	}
	// The existing inbound is a placeholder; validate the generated bridge and rules.
	parsed.InboundConfigs = parsed.InboundConfigs[1:]
	if _, err := parsed.Build(); err != nil {
		t.Fatalf("generated SOCKS routing rejected by Xray: %v", err)
	}
}

func TestTelegramInboundProxyUsesLocalAddressAndCredentials(t *testing.T) {
	inbound := &model.Inbound{
		Enable: true, Protocol: model.Mixed, Listen: "::", Port: 1080,
		Settings: `{"auth":"password","accounts":[{"user":"alice@local","pass":"p:/#?"}]}`,
	}
	address, err := telegramInboundProxy(inbound)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := parseTelegramProxy(address)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := proxy.User.Password()
	if proxy.Host != "[::1]:1080" || proxy.User.Username() != "alice@local" || password != "p:/#?" {
		t.Fatal("the SOCKS5 address did not preserve the host and credentials")
	}
	inbound.StreamSettings = `{"network":"ws","security":"tls"}`
	if _, err := telegramInboundProxy(inbound); err == nil {
		t.Fatal("accepted a non-plain SOCKS transport")
	}
	if _, err := (&Tgbot{}).NewBot("ignored", "http://proxy.example:1080", ""); err == nil {
		t.Fatal("invalid SOCKS proxy must fail rather than connect directly")
	}
}

func TestTelegramClientDialsLocalAPIServerThroughSOCKS(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	target := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
			return
		}
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		var request [5]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 3 {
			return
		}
		address := make([]byte, int(request[4])+2)
		if _, err := io.ReadFull(conn, address); err != nil {
			return
		}
		target <- string(address[:len(address)-2])
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	}()
	endpoint, err := parseTelegramProxy("socks5://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := (&Tgbot{}).createRobustFastHTTPClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial("localhost:8081")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case host := <-target:
		if host != "localhost" {
			t.Fatalf("proxy received the wrong destination: %s", host)
		}
	default:
		t.Fatal("connection bypassed the SOCKS proxy")
	}
}
