// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CeremonyTTL is how long a started ceremony waits for the browser's answer.
// It is also the timeout the browser is told, and the library enforces the
// same limit on its own clock.
const CeremonyTTL = 5 * time.Minute

// maxPending bounds the ceremonies held in memory. Login ceremonies can be
// started without signing in, so this is what stops a flood of them from
// growing memory; past it the oldest is dropped (the owner just retries).
const maxPending = 32

var (
	// ErrNoCeremony means the ceremony id is unknown, expired, already used
	// (every finish attempt consumes it, right or wrong) or of the other kind.
	ErrNoCeremony = errors.New("no such passkey ceremony, or it expired; start again")
	// ErrNoPasskeys means there is nothing registered to log in with.
	ErrNoPasskeys = errors.New("no passkeys are registered")
	// ErrRejected means the library refused the browser's response: wrong
	// origin, RP ID, challenge or signature, no user verification, an
	// unknown or revoked credential, or malformed data.
	ErrRejected = errors.New("passkey response rejected")
	// ErrCloned means the authenticator's signature counter went backwards,
	// the WebAuthn signal that its key may have been copied.
	ErrCloned = errors.New("this passkey's signature counter went backwards, which can mean it was cloned; it was refused")
)

type ceremonyKind int

const (
	kindRegister ceremonyKind = iota + 1
	kindLogin
)

type pending struct {
	kind    ceremonyKind
	session webauthn.SessionData
	name    string // registration only
	expires time.Time
	seq     uint64
}

// Service runs passkey ceremonies for the portal's single owner.
type Service struct {
	rp    RelyingParty
	store *Store
	now   func() time.Time
	wa    *webauthn.WebAuthn

	mu      sync.Mutex
	pending map[string]pending
	seq     uint64
}

// NewService configures the library for rp. now is the clock for ceremony
// expiry (nil means time.Now).
func NewService(rp RelyingParty, store *Store, now func() time.Time) (*Service, error) {
	if rp.ID == "" {
		return nil, ErrNotConfigured
	}
	if now == nil {
		now = time.Now
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rp.ID,
		RPDisplayName: "Shepherd",
		RPOrigins:     rp.Origins,
		// No attestation: Shepherd does not restrict which authenticator
		// makes, so it has no use for a vendor certificate (and asking
		// for one makes some platforms prompt about it).
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Discoverable when the authenticator can, but hardware keys
			// with no room for resident credentials still work: login
			// lists the registered credential ids anyway.
			ResidentKey: protocol.ResidentKeyRequirementPreferred,
			// A passkey replaces a PIN plus a trusted browser (two
			// factors), so the authenticator must verify the person too
			// (biometric or device PIN), not just that someone touched it.
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
		// No extension output feeds any decision here, so an output a
		// browser or password manager adds unprompted is ignored rather
		// than failing an otherwise valid ceremony.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		return nil, err
	}
	return &Service{rp: rp, store: store, now: now, wa: wa, pending: map[string]pending{}}, nil
}

// RP is the relying party this service runs ceremonies for.
func (s *Service) RP() RelyingParty { return s.rp }

// owner is the portal's one WebAuthn user.
type owner struct {
	handle []byte
	creds  []webauthn.Credential
}

func (o owner) WebAuthnID() []byte                         { return o.handle }
func (o owner) WebAuthnName() string                       { return "Shepherd portal" }
func (o owner) WebAuthnDisplayName() string                { return "Shepherd portal" }
func (o owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

func (s *Service) owner() (owner, error) {
	h, err := s.store.UserHandle()
	if err != nil {
		return owner{}, err
	}
	return owner{handle: h, creds: s.store.CredentialsFor(s.rp.ID)}, nil
}

// Usable counts the passkeys that can sign in here: those registered
// under this relying party's ID.
func (s *Service) Usable() int { return len(s.store.CredentialsFor(s.rp.ID)) }

// BeginRegistration starts adding a passkey named name and returns the
// ceremony id and the options to hand to navigator.credentials.create. The
// name and the passkey cap are checked first, so a ceremony that could not
// be saved is never started.
func (s *Service) BeginRegistration(name string) (string, []byte, error) {
	n, err := normalizeName(name)
	if err != nil {
		return "", nil, err
	}
	if s.store.Len() >= MaxPasskeys {
		return "", nil, ErrTooMany
	}
	o, err := s.owner()
	if err != nil {
		return "", nil, err
	}
	creation, session, err := s.wa.BeginRegistration(o,
		webauthn.WithExclusions(webauthn.Credentials(o.creds).CredentialDescriptors()),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return "", nil, err
	}
	opts, _ := json.Marshal(creation) // plain strings, numbers and byte slices: cannot fail
	return s.put(kindRegister, *session, n), opts, nil
}

// FinishRegistration verifies the browser's response to BeginRegistration
// and stores the new passkey.
func (s *Service) FinishRegistration(ceremonyID string, response []byte) (Passkey, error) {
	p, ok := s.take(ceremonyID, kindRegister)
	if !ok {
		return Passkey{}, ErrNoCeremony
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Passkey{}, rejected(err)
	}
	o, err := s.owner()
	if err != nil {
		return Passkey{}, err
	}
	cred, err := s.wa.CreateCredential(o, p.session, parsed)
	if err != nil {
		return Passkey{}, rejected(err)
	}
	return s.store.Add(p.name, s.rp.ID, *cred, s.now())
}

// BeginLogin starts a login and returns the ceremony id and the options to
// hand to navigator.credentials.get. The options list every registered
// credential id, so hardware keys without discoverable credentials work.
func (s *Service) BeginLogin() (string, []byte, error) {
	o, err := s.owner()
	if err != nil {
		return "", nil, err
	}
	if len(o.creds) == 0 {
		return "", nil, ErrNoPasskeys
	}
	assertion, session, err := s.wa.BeginLogin(o)
	if err != nil {
		return "", nil, err
	}
	opts, _ := json.Marshal(assertion) // plain strings, numbers and byte slices: cannot fail
	return s.put(kindLogin, *session, ""), opts, nil
}

// FinishLogin verifies the browser's response to BeginLogin and returns the
// passkey that signed it, with its new counter and last-used time saved.
func (s *Service) FinishLogin(ceremonyID string, response []byte) (Passkey, error) {
	p, ok := s.take(ceremonyID, kindLogin)
	if !ok {
		return Passkey{}, ErrNoCeremony
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Passkey{}, rejected(err)
	}
	o, err := s.owner()
	if err != nil {
		return Passkey{}, err
	}
	cred, err := s.wa.ValidateLogin(o, p.session, parsed)
	if err != nil {
		return Passkey{}, rejected(err)
	}
	if cred.Authenticator.CloneWarning {
		// The specification leaves the response to the relying party; a
		// portal that guards a home network refuses. The stored counter is
		// left alone, and the owner can revoke the passkey and use the PIN
		// or token instead.
		return Passkey{}, ErrCloned
	}
	return s.store.RecordLogin(*cred, s.now())
}

// rejected wraps a library error as ErrRejected, keeping the library's own
// explanation (its Details, plus DevInfo when it names the exact check that
// failed). Callers decide how much of that a client gets to see.
func rejected(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		if pe.DevInfo != "" {
			return fmt.Errorf("%w: %s (%s)", ErrRejected, pe.Details, pe.DevInfo)
		}
		return fmt.Errorf("%w: %s", ErrRejected, pe.Details)
	}
	return fmt.Errorf("%w: %v", ErrRejected, err)
}

// put remembers a started ceremony under a fresh random id, dropping
// expired ones and, past maxPending, the oldest.
func (s *Service) put(kind ceremonyKind, session webauthn.SessionData, name string) string {
	id := hex.EncodeToString(randBytes(32))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	for len(s.pending) >= maxPending {
		oldest, seq := "", ^uint64(0)
		for k, p := range s.pending {
			if p.seq < seq {
				oldest, seq = k, p.seq
			}
		}
		delete(s.pending, oldest)
	}
	s.seq++
	s.pending[id] = pending{kind: kind, session: session, name: name, expires: now.Add(CeremonyTTL), seq: s.seq}
	return id
}

// take removes and returns a ceremony, whatever happens next: a ceremony
// is single use, right or wrong.
func (s *Service) take(id string, kind ceremonyKind) (pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return pending{}, false
	}
	delete(s.pending, id)
	if p.kind != kind || !s.now().Before(p.expires) {
		return pending{}, false
	}
	return p, true
}

func (s *Service) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}
