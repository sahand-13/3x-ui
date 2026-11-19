package service

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

const GiB int64 = 1 << 30

var (
	ErrResellerQuota  = errors.New("اعتبار کافی نیست یا مقدار سهمیه نامعتبر است.")
	ErrResellerInput  = errors.New("اطلاعات واردشده معتبر نیست یا قبلاً ثبت شده است.")
	ErrResellerTarget = errors.New("مورد انتخاب‌شده در دسترس نیست.")
	resellerUsername  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,48}$`)
)

type ResellerService struct{}

type ResellerActor struct {
	RootID int
	ID     int // zero when using the existing administrator session
}

func (a ResellerActor) ownerID() int {
	if a.ID == 0 {
		return -a.RootID
	}
	return a.ID
}

type ResellerInbound struct {
	ID       int
	Remark   string
	Protocol model.Protocol
}

type OwnedClient struct {
	Name, SubID     string
	Total, Up, Down int64
	Enable          bool
}

func (c OwnedClient) LimitGiB() int64 { return c.Total / GiB }
func (c OwnedClient) UsedGiB() float64 { return (float64(c.Up) + float64(c.Down)) / float64(GiB) }

func (s ResellerService) Authenticate(username, password string) (*model.Reseller, error) {
	var account model.Reseller
	if !resellerUsername.MatchString(username) || len(password) > 72 {
		return nil, ErrResellerInput
	}
	if err := database.GetDB().Where("username = ?", username).First(&account).Error; err != nil {
		return nil, err
	}
	if !crypto.CheckPasswordHash(account.PasswordHash, password) {
		return nil, ErrResellerInput
	}
	return &account, nil
}

func (s ResellerService) Account(id int) (*model.Reseller, error) {
	var account model.Reseller
	err := database.GetDB().First(&account, id).Error
	return &account, err
}

func (s ResellerService) Children(actor ResellerActor) ([]model.Reseller, error) {
	var children []model.Reseller
	err := database.GetDB().Omit("password_hash").Where("root_id = ? AND parent_id = ?", actor.RootID, actor.ID).
		Order("id").Find(&children).Error
	return children, err
}

func (s ResellerService) CreateChild(actor ResellerActor, username, password, mode string) error {
	if !resellerUsername.MatchString(username) || len(password) < 12 || len(password) > 72 {
		return ErrResellerInput
	}
	child := model.Reseller{RootID: actor.RootID, ParentID: actor.ID, Username: username}
	if actor.ID == 0 {
		switch mode {
		case "volume":
			child.LimitVolume = true
		case "count":
			child.LimitCount = true
		case "both":
			child.LimitVolume, child.LimitCount = true, true
		default:
			return ErrResellerInput
		}
	} else {
		parent, err := s.Account(actor.ID)
		if err != nil {
			return err
		}
		child.LimitVolume, child.LimitCount = parent.LimitVolume, parent.LimitCount
	}
	hash, err := crypto.HashPasswordAsBcrypt(password)
	if err != nil {
		return err
	}
	child.PasswordHash = hash
	return database.GetDB().Create(&child).Error
}

func debitReseller(tx *gorm.DB, actor ResellerActor, bytes, count int64) error {
	if actor.ID == 0 {
		return nil
	}
	result := tx.Model(&model.Reseller{}).
		Where("id = ? AND root_id = ? AND bytes_left >= ? AND clients_left >= ?", actor.ID, actor.RootID, bytes, count).
		UpdateColumns(map[string]any{
			"bytes_left": gorm.Expr("bytes_left - ?", bytes),
			"clients_left": gorm.Expr("clients_left - ?", count),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrResellerQuota
	}
	return nil
}

func (s ResellerService) Grant(actor ResellerActor, childID int, bytes, count int64) error {
	if childID <= 0 || bytes < 0 || count < 0 || (bytes == 0 && count == 0) {
		return ErrResellerInput
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		child := tx.Model(&model.Reseller{}).Where("id = ? AND root_id = ? AND parent_id = ?", childID, actor.RootID, actor.ID)
		if bytes > 0 {
			child = child.Where("limit_volume = ? AND bytes_left <= ?", true, int64(math.MaxInt64)-bytes)
		}
		if count > 0 {
			child = child.Where("limit_count = ? AND clients_left <= ?", true, int64(math.MaxInt64)-count)
		}
		result := child.UpdateColumns(map[string]any{
			"bytes_left": gorm.Expr("bytes_left + ?", bytes),
			"clients_left": gorm.Expr("clients_left + ?", count),
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrResellerTarget
		}
		return debitReseller(tx, actor, bytes, count)
	})
}

func (s ResellerService) Inbounds(actor ResellerActor) ([]ResellerInbound, error) {
	var inbounds []ResellerInbound
	err := database.GetDB().Model(&model.Inbound{}).Select("id", "remark", "protocol").
		Where("user_id = ? AND enable = ? AND protocol IN ?", actor.RootID, true, []string{"vless", "vmess", "trojan"}).
		Order("id").Find(&inbounds).Error
	return inbounds, err
}

func (s ResellerService) CreateClient(actor ResellerActor, inboundID int, name string, total int64) error {
	if inboundID <= 0 || name == "" || len(name) > 200 || total < 0 {
		return ErrResellerInput
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	subID, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	err = database.GetDB().Transaction(func(tx *gorm.DB) error {
		// Read the current policy from the database; never accept it from the form.
		if actor.ID != 0 {
			var account model.Reseller
			if err := tx.Where("id = ? AND root_id = ?", actor.ID, actor.RootID).First(&account).Error; err != nil {
				return err
			}
			var bytes, count int64
			if account.LimitVolume {
				if total == 0 {
					return ErrResellerQuota
				}
				bytes = total
			}
			if account.LimitCount {
				count = 1
			}
			if err := debitReseller(tx, actor, bytes, count); err != nil {
				return err
			}
		}
		var inbound model.Inbound
		if err := tx.Where("id = ? AND user_id = ? AND enable = ?", inboundID, actor.RootID, true).First(&inbound).Error; err != nil {
			return err
		}
		client := model.Client{
			Email: "reseller-" + id.String(), Comment: name, SubID: subID.String(),
			Enable: true, TotalGB: total, CreatedAt: time.Now().UnixMilli(),
		}
		client.UpdatedAt = client.CreatedAt
		switch inbound.Protocol {
		case "vless", "vmess":
			client.ID = id.String()
		case "trojan":
			client.Password = id.String()
		default:
			return ErrResellerTarget
		}
		var settings map[string]json.RawMessage
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil || settings == nil {
			return ErrResellerTarget
		}
		var clients []json.RawMessage
		if existing := settings["clients"]; existing != nil {
			if err := json.Unmarshal(existing, &clients); err != nil {
				return err
			}
		}
		raw, err := json.Marshal(client)
		if err != nil {
			return err
		}
		settings["clients"], err = json.Marshal(append(clients, raw))
		if err != nil {
			return err
		}
		updated, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		result := tx.Model(&model.Inbound{}).Where("id = ? AND settings = ?", inbound.Id, inbound.Settings).
			Update("settings", string(updated))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrResellerTarget
		}
		inboundService := InboundService{}
		if err := inboundService.AddClientStat(tx, inboundID, &client); err != nil {
			return err
		}
		return tx.Create(&model.ResellerClient{SubID: client.SubID, OwnerID: actor.ownerID(), InboundID: inboundID}).Error
	})
	if err == nil {
		(&XrayService{}).SetToNeedRestart()
	}
	return err
}

func (s ResellerService) Clients(actor ResellerActor) ([]OwnedClient, error) {
	db := database.GetDB()
	var ownership []model.ResellerClient
	if err := db.Where("owner_id = ?", actor.ownerID()).Find(&ownership).Error; err != nil {
		return nil, err
	}
	if len(ownership) == 0 {
		return nil, nil
	}
	byInbound := make(map[int]map[string]bool)
	var inboundIDs []int
	for _, record := range ownership {
		if byInbound[record.InboundID] == nil {
			byInbound[record.InboundID] = make(map[string]bool)
			inboundIDs = append(inboundIDs, record.InboundID)
		}
		byInbound[record.InboundID][record.SubID] = true
	}
	var inbounds []model.Inbound
	if err := db.Preload("ClientStats").Where("user_id = ? AND id IN ?", actor.RootID, inboundIDs).Order("id").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	var owned []OwnedClient
	inboundService := InboundService{}
	for _, inbound := range inbounds {
		clients, err := inboundService.GetClients(&inbound)
		if err != nil {
			return nil, err
		}
		stats := make(map[string]xray.ClientTraffic, len(inbound.ClientStats))
		for _, stat := range inbound.ClientStats {
			stats[stat.Email] = stat
		}
		for _, client := range clients {
			if byInbound[inbound.Id][client.SubID] {
				stat := stats[client.Email]
				owned = append(owned, OwnedClient{
					Name: client.Comment, SubID: client.SubID, Total: client.TotalGB,
					Up: stat.Up, Down: stat.Down, Enable: client.Enable && stat.Enable && inbound.Enable,
				})
			}
		}
	}
	return owned, nil
}
