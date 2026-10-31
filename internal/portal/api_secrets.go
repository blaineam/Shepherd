// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"shepherd/internal/secrets"
)

// The two portal-managed secrets (internal/secrets): the DNS provider token
// [tls] and [reverseproxy] share, and the accountability mail relay. Both
// are write-only through this API: a saved token or password is never sent
// back, only whether one is set, where it came from and when it changed.
//
// Every save is checked first with a real, side-effect-free call
// (Deps.VerifyDNSProvider / Deps.VerifySMTP) and refused with 422 when the
// check fails, so a bad credential is reported now rather than when a
// certificate renewal or a digest email fails hours later. Nothing is stored
// on a refusal.

// Secret kinds passed to Deps.OnSecretsChanged.
const (
	SecretDNSProvider = "dns_provider"
	SecretSMTP        = "smtp"
)

// refused answers 422 for a credential that failed its check, phrased as a
// sentence for the person who just pressed Save.
func refused(w http.ResponseWriter, err error) {
	msg := err.Error()
	if r, size := utf8.DecodeRuneInString(msg); size > 0 {
		msg = string(unicode.ToUpper(r)) + msg[size:]
	}
	http.Error(w, msg+". Nothing was saved.", http.StatusUnprocessableEntity)
}

// secretError maps a store error: bad input is 400, anything else is a save
// the disk refused (500, without echoing the error).
func secretError(w http.ResponseWriter, err error) {
	if errors.Is(err, secrets.ErrInvalid) {
		bad(w, err.Error())
		return
	}
	serverFault(w, "could not save the secret")
}

func (s *Server) secretsChanged(kind string) {
	if s.OnSecretsChanged != nil {
		s.OnSecretsChanged(kind)
	}
}

func updatedAt(m secrets.Meta) *time.Time {
	if m.UpdatedAt.IsZero() {
		return nil
	}
	t := m.UpdatedAt.UTC()
	return &t
}

// --- DNS provider ---

type dnsProviderJSON struct {
	Provider   string     `json:"provider"`
	Configured bool       `json:"configured"`
	Source     string     `json:"source,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	// UsedBy names the enabled features that issue certificates with it.
	UsedBy []string `json:"used_by"`
	// Providers lists every provider this version can use.
	Providers []string `json:"providers"`
}

func (s *Server) dnsProviderDoc() dnsProviderJSON {
	d, ok := s.Secrets.DNSProvider()
	out := dnsProviderJSON{Provider: d.Provider, Configured: ok, UsedBy: orEmpty(s.DNSProviderUsers), Providers: []string{secrets.ProviderCloudflare}}
	if out.Provider == "" {
		out.Provider = secrets.ProviderCloudflare
	}
	if s.Secrets.DNSProviderManaged() {
		out.Source, out.UpdatedAt = d.Source, updatedAt(d.Meta)
	}
	return out
}

func (s *Server) getDNSProvider(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.dnsProviderDoc())
}

func (s *Server) putDNSProvider(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Provider string `json:"provider"`
		APIToken string `json:"api_token"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Provider == "" {
		b.Provider = secrets.ProviderCloudflare
	}
	d, err := secrets.DNSProvider{Provider: b.Provider, APIToken: b.APIToken}.Normalize()
	if err != nil {
		bad(w, err.Error())
		return
	}
	if s.VerifyDNSProvider != nil {
		if err := s.VerifyDNSProvider(r.Context(), d); err != nil {
			refused(w, err)
			return
		}
	}
	if _, err := s.Secrets.SetDNSProvider(d); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretDNSProvider)
	writeJSON(w, s.dnsProviderDoc())
}

func (s *Server) deleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	if err := s.Secrets.ClearDNSProvider(); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretDNSProvider)
	writeJSON(w, s.dnsProviderDoc())
}

// --- Accountability mail relay ---

// Defaults a blank relay form starts from: the submission port with
// STARTTLS, the convention most providers document.
const (
	defaultSMTPPort = 587
	defaultSMTPTLS  = "starttls"
)

type smtpJSON struct {
	// Enabled is whether accountability is on in shepherd.toml at all.
	// The relay can be saved either way; it is only used when enabled.
	Enabled    bool `json:"enabled"`
	Configured bool `json:"configured"`
	// Active is whether outgoing mail goes through this relay right now:
	// configured and enabled. A save applies at once, with no restart.
	Active      bool       `json:"active"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Username    string     `json:"username"`
	PasswordSet bool       `json:"password_set"`
	From        string     `json:"from"`
	TLS         string     `json:"tls"`
	Source      string     `json:"source,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func (s *Server) smtpDoc() smtpJSON {
	m, ok := s.Secrets.SMTP()
	out := smtpJSON{Enabled: s.Accountability != nil, Configured: ok, Port: defaultSMTPPort, TLS: defaultSMTPTLS}
	out.Active = out.Enabled && ok
	if ok {
		out.Host, out.Port, out.Username, out.From, out.TLS = m.Host, m.Port, m.Username, m.From, m.TLS
		out.PasswordSet = m.Password != ""
	}
	if s.Secrets.SMTPManaged() {
		out.Source, out.UpdatedAt = m.Source, updatedAt(m.Meta)
	}
	return out
}

func (s *Server) getSMTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.smtpDoc())
}

func (s *Server) putSMTP(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		// Password left empty keeps the saved one — but only for the same
		// host and username, so a stored password can never be pointed at
		// a different server (that would be a way to read it back).
		Password      string `json:"password"`
		ClearPassword bool   `json:"clear_password"`
		From          string `json:"from"`
		TLS           string `json:"tls"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.TLS == "" {
		b.TLS = defaultSMTPTLS
	}
	m, err := secrets.SMTP{Host: b.Host, Port: b.Port, Username: b.Username, Password: b.Password, From: b.From, TLS: b.TLS}.Normalize()
	if err != nil {
		bad(w, err.Error())
		return
	}
	if m.Password == "" && !b.ClearPassword {
		cur, ok := s.Secrets.SMTP()
		switch {
		case ok && cur.Password != "" && cur.Host == m.Host && cur.Username == m.Username:
			m.Password = cur.Password
		case ok && cur.Password != "" && m.Username != "":
			bad(w, "enter the password again: the relay host or username changed, and a saved password is only ever sent to the server it was entered for")
			return
		}
	}
	if s.VerifySMTP != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		err := s.VerifySMTP(ctx, m)
		cancel()
		if err != nil {
			refused(w, err)
			return
		}
	}
	if _, err := s.Secrets.SetSMTP(m); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretSMTP)
	writeJSON(w, s.smtpDoc())
}

func (s *Server) deleteSMTP(w http.ResponseWriter, r *http.Request) {
	if err := s.Secrets.ClearSMTP(); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretSMTP)
	writeJSON(w, s.smtpDoc())
}
