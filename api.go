package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/starkandwayne/safe/vault"
)

func wrap(path string, thing interface{}) interface{} {
	out := struct {
		Path   string      `json:"path"`
		Type   string      `json:"type"`
		Secret interface{} `json:"secret"`
	}{
		Type:   "secret",
		Path:   path,
		Secret: thing,
	}

	if has(thing, "private") && has(thing, "public") {
		if has(thing, "fingerprint") {
			out.Type = "ssh"
		} else {
			out.Type = "rsa"
		}
	} else if has(thing, "certificate") && has(thing, "key") {
		if has(thing, "crl") && has(thing, "serial") {
			out.Type = "ca"
		} else {
			out.Type = "cert"
		}
	}

	return out
}

type API struct {
	memory map[string]map[string]string
	last   rune
	prefix string
	vault  *vault.Vault
	lock   sync.Mutex
}

func NewAPI(url, token, prefix string) (*API, error) {
	v, err := vault.NewVault(url, token, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to authenticate to Vault at '%s': %s\n", url, err)
	}

	if prefix != "" {
		prefix = strings.Trim(prefix, "/")
	}
	return &API{
		memory: make(map[string]map[string]string),
		last:   'a',
		prefix: prefix,
		vault:  v,
	}, nil
}

func (a *API) sync() {
	root := a.prefix

	tree, err := a.vault.Tree(root, vault.TreeOptions{
		ShowKeys:     true,
		StripSlashes: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bg] failed to walk %s: %s\n", a.prefix, err)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	if a.memory == nil {
		a.memory = make(map[string]map[string]string)
	}
	a.last++
	last := string(a.last)

	root += "/"
	for _, path := range tree.Paths("/") {
		l := strings.SplitN(strings.TrimPrefix(path, root), ":", 2)
		path = strings.TrimSuffix(l[0], "/")
		key := l[1]

		if a.memory[path] == nil {
			a.memory[path] = make(map[string]string)
		}
		a.memory[path][key] = last
	}

	for _, memory := range a.memory {
		for k := range memory {
			if memory[k] != last {
				delete(memory, k)
			}
		}
	}
}

func (a *API) Background(seconds int) {
	t := time.NewTicker(time.Duration(seconds) * time.Second)

	a.sync()
	for range t.C {
		a.sync()
	}
}

func (a *API) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/v1/secret" {
		if req.Method == "GET" {
			l := make([]interface{}, 0)
			q := req.URL.Query().Get("q")

			for path, v := range a.memory {
				if strings.Contains(path, q) {
					l = append(l, wrap(path, v))
				}
			}

			reply(200, w, l)
			return
		}

		w.WriteHeader(405)
		fmt.Fprintf(w, "method not allowed\n")
		return
	}

	if strings.HasPrefix(req.URL.Path, "/v1/secret/") {
		root := a.prefix + "/"
		path := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v1/secret/"), "/")

		if req.Method == "GET" {
			v, err := a.vault.Read(root + path)
			if err != nil {
				oops(500, w, err)
				return
			}
			if v == nil {
				oops(404, w, fmt.Errorf("secret '%s' not found", path))
				return
			}
			reply(200, w, wrap(path, v.Data()))
			return
		}

		if req.Method == "PUT" {
			var in struct {
				Type   string            `json:"type"`
				Secret map[string]string `json:"secret"`

				SSH struct {
					Bits int `json:"bits"`
				} `json:"ssh"`

				RSA struct {
					Bits int `json:"bits"`
				} `json:"rsa"`

				X509 struct {
					Subject string   `json:"subject"`
					Issuer  string   `json:"issuer"`
					TTL     string   `json:"ttl"`
					SANs    []string `json:"sans"`
					CA      bool     `json:"ca"`
				} `json:"x509"`
			}
			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				oops(500, w, err)
				return
			}
			err = json.Unmarshal(b, &in)
			if err != nil {
				oops(400, w, err)
				return
			}

			if path == "" {
				oops(400, w, fmt.Errorf("no secret path specified"))
				return
			}

			secret := vault.NewSecret()
			switch in.Type {
			case "secret":
				if len(in.Secret) == 0 {
					oops(400, w, fmt.Errorf("no secret keys specified"))
					return
				}
				for k, v := range in.Secret {
					secret.Set(k, v, false)
				}

			case "ssh":
				switch in.SSH.Bits {
				case 1024, 2048, 4096:
				default:
					oops(400, w, fmt.Errorf("invalid SSH key strength '%d' (not 1024, 2048, or 4096)", in.SSH.Bits))
					return
				}
				err = secret.SSHKey(in.SSH.Bits, false)
				if err != nil {
					oops(500, w, err)
					return
				}

			case "rsa":
				switch in.RSA.Bits {
				case 1024, 2048, 4096:
				default:
					oops(400, w, fmt.Errorf("invalid RSA key strength '%d' (not 1024, 2048, or 4096)", in.RSA.Bits))
					return
				}
				err = secret.RSAKey(in.RSA.Bits, false)
				if err != nil {
					oops(500, w, err)
					return
				}

			case "ca", "cert":
				var ca *vault.X509

				ttl, err := vault.Duration(in.X509.TTL)
				if err != nil {
					oops(400, w, fmt.Errorf("invalid ttl"))
					return
				}
				if len(in.X509.SANs) == 0 {
					oops(400, w, fmt.Errorf("no subject alternate names given"))
					return
				}
				if in.X509.Issuer != "" {
					secret, err := a.vault.Read(root+in.X509.Issuer)
					if err != nil {
						oops(404, w, fmt.Errorf("unable to find CA: %s", err))
						return
					}
					ca, err = secret.X509()
					if err != nil {
						oops(400, w, fmt.Errorf("%s is not a CA", path, err))
						return
					}
				}

				if in.X509.Subject == "" {
					in.X509.Subject = "cn=" + in.X509.SANs[0]
				}
				cert, err := vault.NewCertificate(in.X509.Subject, in.X509.SANs, nil, 2048)
				if err != nil {
					oops(500, w, err)
					return
				}

				if in.X509.CA {
					cert.MakeCA(1)
				}
				if ca == nil {
					if err = cert.Sign(cert, ttl); err != nil {
						oops(500, w, err)
						return
					}
				} else {
					if err = ca.Sign(cert, ttl); err != nil {
						oops(500, w, err)
						return
					}
					s, err := ca.Secret(false)
					if err != nil {
						oops(500, w, err)
						return
					}
					if err = a.vault.Write(root+in.X509.Issuer, s); err != nil {
						oops(500, w, err)
						return
					}
				}

				secret, err = cert.Secret(false)
				if err != nil {
					oops(500, w, err)
					return
				}
			}

			err = a.vault.Write(root+path, secret)
			if err != nil {
				oops(500, w, err)
				return
			}

			a.sync()
			reply(200, w, wrap(path, secret.Data()))
			return
		}

		if req.Method == "DELETE" {
			delete(a.memory, path)
			reply(200, w, ok("deleted"))
			return
		}

		w.WriteHeader(405)
		fmt.Fprintf(w, "method not allowed\n")
		return
	}

	w.WriteHeader(404)
	fmt.Fprintf(w, "endpoint not found\n")
}
