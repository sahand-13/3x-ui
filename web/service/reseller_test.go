package service

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestResellerOwnershipAndQuota(t *testing.T) {
	if err := database.InitDB(filepath.ToSlash(filepath.Join(t.TempDir(), "resellers.db"))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
	s := ResellerService{}
	root := ResellerActor{RootID: 1}
	db := database.GetDB()
	inbound := model.Inbound{UserId: root.RootID, Enable: true, Protocol: model.VLESS, Tag: "reseller-test", Settings: `{"clients":[]}`}
	if err := db.Create(&inbound).Error; err != nil {
		t.Fatal(err)
	}
	insert := func(parent ResellerActor, name string) ResellerActor {
		t.Helper()
		if err := s.CreateChild(parent, name, "example-password", "both"); err != nil {
			t.Fatal(err)
		}
		account, err := s.Authenticate(name, "example-password")
		if err != nil {
			t.Fatal(err)
		}
		return ResellerActor{RootID: account.RootID, ID: account.ID}
	}
	parent := insert(root, "parent")
	child := insert(parent, "child")
	sibling := insert(root, "sibling")
	if err := s.Grant(root, parent.ID, 4*GiB, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(root, child.ID, GiB, 1); !errors.Is(err, ErrResellerTarget) {
		t.Fatalf("grant to indirect child: %v", err)
	}
	if err := s.Grant(parent, child.ID, 5*GiB, 1); !errors.Is(err, ErrResellerQuota) {
		t.Fatalf("grant above parent's balance: %v", err)
	}
	if account, err := s.Account(child.ID); err != nil || account.BytesLeft != 0 || account.ClientsLeft != 0 {
		t.Fatalf("failed grant changed child's balance: %+v, %v", account, err)
	}
	if err := s.Grant(parent, child.ID, 3*GiB, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(child, inbound.Id+1, "missing inbound", GiB); err == nil {
		t.Fatal("accepted nonexistent inbound")
	}
	if err := s.CreateClient(parent, inbound.Id, "too large", 2*GiB); !errors.Is(err, ErrResellerQuota) {
		t.Fatalf("created client over volume limit: %v", err)
	}
	if err := s.CreateClient(child, inbound.Id, "child client", 2*GiB); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(child, inbound.Id, "too many", GiB); !errors.Is(err, ErrResellerQuota) {
		t.Fatalf("created client over count limit: %v", err)
	}
	if err := s.CreateClient(parent, inbound.Id, "parent client", GiB); err != nil {
		t.Fatal(err)
	}
	for actor, want := range map[ResellerActor]string{root: "", parent: "parent client", child: "child client", sibling: ""} {
		clients, err := s.Clients(actor)
		if err != nil {
			t.Fatal(err)
		}
		if want == "" {
			if len(clients) != 0 {
				t.Fatalf("actor %d can see someone else's client", actor.ID)
			}
		} else if len(clients) != 1 || clients[0].Name != want || !clients[0].Enable {
			t.Fatalf("actor %d: unexpected clients: %+v", actor.ID, clients)
		}
	}
	for _, mode := range []string{"volume", "count"} {
		if err := s.CreateChild(root, mode, "example-password", mode); err != nil {
			t.Fatal(err)
		}
		account, err := s.Authenticate(mode, "example-password")
		if err != nil {
			t.Fatal(err)
		}
		actor := ResellerActor{RootID: account.RootID, ID: account.ID}
		if mode == "volume" {
			if err := s.Grant(root, actor.ID, GiB, 0); err != nil {
				t.Fatal(err)
			}
			if err := s.CreateClient(actor, inbound.Id, "unlimited", 0); !errors.Is(err, ErrResellerQuota) {
				t.Fatalf("volume limited account created unlimited client: %v", err)
			}
			if err := s.CreateClient(actor, inbound.Id, "limited volume", GiB); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := s.Grant(root, actor.ID, 0, 1); err != nil {
				t.Fatal(err)
			}
			if err := s.CreateClient(actor, inbound.Id, "limited count", 0); err != nil {
				t.Fatal(err)
			}
		}
	}
}
