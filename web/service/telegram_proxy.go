package service

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/entity"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const telegramInboundTag = "3x-ui-telegram-socks"

type telegramProxyAccount struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type telegramBridge struct {
	port    int
	account telegramProxyAccount
}

// Reuse the same local endpoint across Xray restarts while the panel is running.
var getTelegramBridge = sync.OnceValues(func() (telegramBridge, error) {
	password, err := uuid.NewRandom()
	if err != nil {
		return telegramBridge{}, err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return telegramBridge{}, err
	}
	defer listener.Close()
	return telegramBridge{listener.Addr().(*net.TCPAddr).Port, telegramProxyAccount{"telegram", password.String()}}, nil
})

func parseTelegramProxy(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "socks5" && parsed.Scheme != "socks5h") ||
		parsed.Hostname() == "" || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Telegram proxy must use socks5://host:port or socks5://user:pass@host:port")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("Telegram SOCKS5 proxy needs a valid port")
	}
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		if username := parsed.User.Username(); len(username) == 0 || len(username) > 255 || len(password) > 255 {
			return nil, errors.New("Invalid Telegram SOCKS5 credentials")
		}
	}
	return parsed, nil
}

func telegramProxyURL(host string, port int, account *telegramProxyAccount) string {
	endpoint := url.URL{Scheme: "socks5", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if account != nil {
		endpoint.User = url.UserPassword(account.User, account.Pass)
	}
	return endpoint.String()
}

func telegramInboundProxy(inbound *model.Inbound) (string, error) {
	if !inbound.Enable || (inbound.Protocol != model.Mixed && inbound.Protocol != "socks") ||
		inbound.Port < 1 || inbound.Port > 65535 {
		return "", errors.New("Telegram needs an enabled SOCKS or Mixed inbound")
	}
	host := strings.TrimSpace(inbound.Listen)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	default:
		if !net.ParseIP(host).IsLoopback() {
			return "", errors.New("Telegram inbound must listen on a loopback or wildcard IP; use the SOCKS5 URL for other addresses")
		}
	}
	var stream struct {
		Network  string `json:"network"`
		Security string `json:"security"`
	}
	if strings.TrimSpace(inbound.StreamSettings) != "" {
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil {
			return "", errors.New("Invalid Telegram SOCKS inbound transport settings")
		}
	}
	if (stream.Network != "" && stream.Network != "tcp" && stream.Network != "raw") ||
		(stream.Security != "" && stream.Security != "none") {
		return "", errors.New("Telegram SOCKS inbound must use plain TCP")
	}
	var settings struct {
		Auth     string                 `json:"auth"`
		Accounts []telegramProxyAccount `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return "", errors.New("Invalid Telegram SOCKS inbound settings")
	}
	switch settings.Auth {
	case "", "noauth":
		return telegramProxyURL(host, inbound.Port, nil), nil
	case "password":
		for _, account := range settings.Accounts {
			if account.User != "" && len(account.User) <= 255 && account.Pass != "" && len(account.Pass) <= 255 {
				return telegramProxyURL(host, inbound.Port, &account), nil
			}
		}
	}
	return "", errors.New("Telegram SOCKS inbound has no usable authentication account")
}

func loadTelegramInboundProxy(id int) (string, error) {
	if id <= 0 {
		return "", errors.New("Select a SOCKS or Mixed inbound for Telegram")
	}
	inbounds := InboundService{}
	inbound, err := inbounds.GetInbound(id)
	if err != nil {
		return "", errors.New("The selected Telegram inbound is unavailable")
	}
	return telegramInboundProxy(inbound)
}

func validateTelegramOutbound(cfg *xray.Config, tag string) error {
	var outbounds []struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		return errors.New("Cannot read Xray outbounds for Telegram")
	}
	for _, outbound := range outbounds {
		if tag != "" && tag == outbound.Tag {
			return nil
		}
	}
	return errors.New("The selected Telegram outbound is unavailable")
}

func telegramRouting(cfg *xray.Config) (map[string]json.RawMessage, []json.RawMessage, error) {
	routing := make(map[string]json.RawMessage)
	if len(cfg.RouterConfig) != 0 {
		if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
			return nil, nil, errors.New("Cannot read Xray routing for Telegram")
		}
	}
	if routing == nil {
		routing = make(map[string]json.RawMessage)
	}
	var script string
	if raw := routing["script"]; raw != nil {
		if err := json.Unmarshal(raw, &script); err != nil || script != "" {
			return nil, nil, errors.New("Telegram outbound selection is unavailable with an Xray routing script")
		}
	}
	var rules []json.RawMessage
	if raw := routing["rules"]; raw != nil {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return nil, nil, errors.New("Cannot read Xray routing rules for Telegram")
		}
	}
	return routing, rules, nil
}

func (s *SettingService) telegramOutboundTemplate(tag string) error {
	template, err := s.GetXrayConfigTemplate()
	if err != nil {
		return err
	}
	var cfg xray.Config
	if err := json.Unmarshal([]byte(template), &cfg); err != nil {
		return errors.New("Cannot read the Xray template for Telegram")
	}
	if err := validateTelegramOutbound(&cfg, tag); err != nil {
		return err
	}
	_, _, err = telegramRouting(&cfg)
	return err
}

func validateTelegramProxy(s *SettingService, settings *entity.AllSetting) error {
	switch settings.TgBotProxyMode {
	case "direct":
		return nil
	case "", "manual":
		if strings.TrimSpace(settings.TgBotProxy) == "" && settings.TgBotProxyMode == "" {
			return nil
		}
		_, err := parseTelegramProxy(settings.TgBotProxy)
		return err
	case "inbound":
		_, err := loadTelegramInboundProxy(settings.TgBotProxyInbound)
		return err
	case "outbound":
		return s.telegramOutboundTemplate(settings.TgBotProxyOutbound)
	default:
		return errors.New("Invalid Telegram proxy mode")
	}
}

func (s *SettingService) telegramBotProxy() (string, error) {
	mode, err := s.getString("tgBotProxyMode")
	if err != nil {
		return "", err
	}
	switch mode {
	case "direct":
		return "", nil
	case "", "manual":
		raw, err := s.GetTgBotProxy()
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(raw) == "" && mode == "manual" {
			return "", errors.New("Enter a SOCKS5 URL for Telegram")
		}
		return strings.TrimSpace(raw), nil
	case "inbound":
		id, err := s.getInt("tgBotProxyInbound")
		if err != nil {
			return "", err
		}
		return loadTelegramInboundProxy(id)
	case "outbound":
		tag, err := s.getString("tgBotProxyOutbound")
		if err != nil {
			return "", err
		}
		if err := s.telegramOutboundTemplate(tag); err != nil {
			return "", err
		}
		bridge, err := getTelegramBridge()
		if err != nil {
			return "", err
		}
		return telegramProxyURL("127.0.0.1", bridge.port, &bridge.account), nil
	default:
		return "", errors.New("Invalid Telegram proxy mode")
	}
}

func addTelegramBridge(cfg *xray.Config, tag string, bridge telegramBridge) error {
	if err := validateTelegramOutbound(cfg, tag); err != nil {
		return err
	}
	routing, rules, err := telegramRouting(cfg)
	if err != nil {
		return err
	}
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag == telegramInboundTag || inbound.Port == bridge.port {
			return errors.New("Telegram SOCKS bridge conflicts with an Xray inbound")
		}
	}
	config, err := json.Marshal(map[string]any{
		"auth": "password", "accounts": []telegramProxyAccount{bridge.account}, "udp": false,
	})
	if err != nil {
		return err
	}
	rule, err := json.Marshal(map[string]any{
		"type": "field", "inboundTag": []string{telegramInboundTag}, "outboundTag": tag,
	})
	if err != nil {
		return err
	}
	routing["rules"], err = json.Marshal(append([]json.RawMessage{rule}, rules...))
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	cfg.RouterConfig = encoded
	cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{
		Listen: []byte(`"127.0.0.1"`), Port: bridge.port, Protocol: "mixed", Settings: config, Tag: telegramInboundTag,
	})
	return nil
}

func (s *SettingService) configureTelegramBridge(cfg *xray.Config) error {
	mode, err := s.getString("tgBotProxyMode")
	if err != nil || mode != "outbound" {
		return err
	}
	enabled, err := s.GetTgbotEnabled()
	if err != nil || !enabled {
		return err
	}
	tag, err := s.getString("tgBotProxyOutbound")
	if err != nil {
		return err
	}
	bridge, err := getTelegramBridge()
	if err != nil {
		return err
	}
	return addTelegramBridge(cfg, tag, bridge)
}
