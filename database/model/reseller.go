package model

// Reseller is a restricted panel identity. A zero ParentID denotes an
// account directly managed by the administrator identified by RootID.
type Reseller struct {
	ID           int    `gorm:"primaryKey"`
	RootID       int    `gorm:"index:reseller_parent"`
	ParentID     int    `gorm:"index:reseller_parent"`
	Username     string `gorm:"uniqueIndex"`
	PasswordHash string `json:"-"`
	LimitVolume  bool
	LimitCount   bool
	BytesLeft    int64
	ClientsLeft  int64
}

// ResellerClient associates an immutable subscription ID with its creator.
type ResellerClient struct {
	SubID     string `gorm:"primaryKey"`
	OwnerID   int    `gorm:"index"`
	InboundID int
}

func (r Reseller) VolumeLeftGiB() int64 { return r.BytesLeft >> 30 }
