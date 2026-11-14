module shepherd

go 1.26.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/go-webauthn/webauthn v0.18.2
	github.com/miekg/dns v1.1.73
)

require github.com/cilium/ebpf v0.22.0

require (
	github.com/insomniacslk/dhcp v0.0.0-20261014062924-c6bb46ad3f3a
	github.com/josharian/native v1.1.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
)

require (
	github.com/maxmind/mmdbwriter v1.2.0
	github.com/oschwald/maxminddb-golang/v2 v2.9.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
)

tool github.com/cilium/ebpf/cmd/bpf2go

// Pulled in by github.com/go-webauthn/webauthn (docs/PASSKEYS.md).
require (
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)
