package controller

import (
	"crypto/subtle"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
)

const resellerSessionKey = "RESELLER_ID"
const resellerCSRFKey = "RESELLER_CSRF"
const resellerNoticeKey = "RESELLER_NOTICE"

type ResellerController struct {
	resellers service.ResellerService
	settings  service.SettingService
}

func NewResellerController(g *gin.RouterGroup) {
	a := &ResellerController{}
	g = g.Group("/resellers")
	g.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	})
	g.GET("", a.page)
	g.POST("/login", a.checkForm, a.login)
	g.POST("/logout", a.checkForm, a.logout)
	g.POST("/child", a.checkForm, a.createChild)
	g.POST("/grant", a.checkForm, a.grant)
	g.POST("/client", a.checkForm, a.createClient)
}

func (a *ResellerController) checkForm(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
	if err := c.Request.ParseForm(); err != nil || len(c.Request.PostForm["csrf"]) != 1 {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	expected, _ := sessions.Default(c).Get(resellerCSRFKey).(string)
	if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(c.Request.PostForm.Get("csrf"))) != 1 {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}

func (a *ResellerController) actor(c *gin.Context) (service.ResellerActor, *model.Reseller) {
	if admin := session.GetLoginUser(c); admin != nil {
		return service.ResellerActor{RootID: admin.Id}, nil
	}
	if id, ok := sessions.Default(c).Get(resellerSessionKey).(int); ok && id > 0 {
		account, err := a.resellers.Account(id)
		if err == nil {
			return service.ResellerActor{RootID: account.RootID, ID: account.ID}, account
		}
	}
	return service.ResellerActor{}, nil
}

func (a *ResellerController) finish(c *gin.Context, notice string) {
	s := sessions.Default(c)
	if notice != "" {
		s.AddFlash(notice, resellerNoticeKey)
	}
	if err := s.Save(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Redirect(http.StatusSeeOther, c.GetString("base_path")+"resellers")
}

func (a *ResellerController) login(c *gin.Context) {
	actor, _ := a.actor(c)
	if actor.RootID != 0 {
		a.finish(c, "")
		return
	}
	form := c.Request.PostForm
	account, err := a.resellers.Authenticate(strings.TrimSpace(form.Get("username")), form.Get("password"))
	if err != nil {
		a.finish(c, "نام کاربری یا گذرواژه نادرست است.")
		return
	}
	age, err := a.settings.GetSessionMaxAge()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	session.SetMaxAge(c, age*60)
	s := sessions.Default(c)
	s.Set(resellerSessionKey, account.ID)
	s.Delete(resellerCSRFKey)
	a.finish(c, "")
}

func (a *ResellerController) logout(c *gin.Context) {
	s := sessions.Default(c)
	s.Delete(resellerSessionKey)
	s.Delete(resellerCSRFKey)
	a.finish(c, "")
}

func (a *ResellerController) page(c *gin.Context) {
	s := sessions.Default(c)
	token, _ := s.Get(resellerCSRFKey).(string)
	notices := s.Flashes(resellerNoticeKey)
	if token == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		token = id.String()
		s.Set(resellerCSRFKey, token)
	}
	if err := s.Save(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	actor, account := a.actor(c)
	data := gin.H{"csrf": token, "notices": notices, "signed_in": actor.RootID != 0, "root": actor.RootID != 0 && actor.ID == 0, "account": account}
	if actor.RootID != 0 {
		children, childrenErr := a.resellers.Children(actor)
		clients, clientsErr := a.resellers.Clients(actor)
		inbounds, inboundsErr := a.resellers.Inbounds(actor)
		if err := errors.Join(childrenErr, clientsErr, inboundsErr); err != nil {
			logger.Warning("Unable to read reseller panel:", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		data["children"], data["clients"], data["inbounds"] = children, clients, inbounds
		if settings, err := a.settings.GetDefaultSettings(c.Request.Host); err == nil {
			if values, ok := settings.(map[string]any); ok && values["subEnable"] == true {
				if raw, ok := values["subURI"].(string); ok {
					if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" && (parsed.Scheme == "https" || parsed.Scheme == "http") {
						data["subscription"] = strings.TrimRight(raw, "/") + "/"
					}
				}
			}
		}
	}
	html(c, "resellers.html", "مدیریت فروشندگان", data)
}

func (a *ResellerController) action(c *gin.Context, run func(service.ResellerActor, url.Values) error) {
	actor, _ := a.actor(c)
	if actor.RootID == 0 {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if err := run(actor, c.Request.PostForm); err != nil {
		switch {
		case errors.Is(err, service.ErrResellerInput), errors.Is(err, service.ErrResellerQuota), errors.Is(err, service.ErrResellerTarget):
			a.finish(c, err.Error())
		default:
			logger.Warning("Unable to update reseller panel:", err)
			a.finish(c, "عملیات انجام نشد. اطلاعات را بررسی کنید و دوباره تلاش کنید.")
		}
		return
	}
	a.finish(c, "عملیات انجام شد.")
}

func parseQuota(value string, unit int64) (int64, error) {
	if value == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64/unit {
		return 0, service.ErrResellerInput
	}
	return n * unit, nil
}

func (a *ResellerController) createChild(c *gin.Context) {
	a.action(c, func(actor service.ResellerActor, form url.Values) error {
		return a.resellers.CreateChild(actor, strings.TrimSpace(form.Get("username")), form.Get("password"), form.Get("mode"))
	})
}

func (a *ResellerController) grant(c *gin.Context) {
	a.action(c, func(actor service.ResellerActor, form url.Values) error {
		child, err := strconv.Atoi(form.Get("child"))
		if err != nil {
			return service.ErrResellerInput
		}
		bytes, err := parseQuota(form.Get("volume"), service.GiB)
		if err != nil {
			return err
		}
		count, err := parseQuota(form.Get("count"), 1)
		if err != nil {
			return err
		}
		return a.resellers.Grant(actor, child, bytes, count)
	})
}

func (a *ResellerController) createClient(c *gin.Context) {
	a.action(c, func(actor service.ResellerActor, form url.Values) error {
		inbound, err := strconv.Atoi(form.Get("inbound"))
		if err != nil {
			return service.ErrResellerInput
		}
		bytes, err := parseQuota(form.Get("volume"), service.GiB)
		if err != nil {
			return err
		}
		return a.resellers.CreateClient(actor, inbound, strings.TrimSpace(form.Get("name")), bytes)
	})
}
