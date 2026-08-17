// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

import (
	"strings"
	"sync"
)

// SNIRouter selects a server context by the SNI name of an incoming
// handshake. Names are normalized (lowercased, one trailing dot stripped) and
// a wildcard entry "*.example.com" matches every name sharing that parent
// domain.
type SNIRouter struct {
	mu     sync.RWMutex
	byName map[string]*Ctx
}

func NewSNIRouter() *SNIRouter {
	return &SNIRouter{byName: make(map[string]*Ctx)}
}

// Add registers ctx under name, normalizing it first.
func (r *SNIRouter) Add(name string, ctx *Ctx) {
	name = normalizeSNI(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[name] = ctx
}

// Lookup returns the context registered for name, trying the wildcard entry
// of the name's parent domain next. It returns nil when nothing matches.
func (r *SNIRouter) Lookup(name string) *Ctx {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ctx, _ := SNILookup(r.byName, name)
	return ctx
}

// Install registers an SNI switching callback on every context so incoming
// handshakes are dispatched through the router. The callback returns
// SSLTLSExtErrNoAck when no entry matches, leaving the listening context in
// place; panics inside a matching lookup surface as a fatal alert.
func (r *SNIRouter) Install(ctxs ...*Ctx) {
	for _, ctx := range ctxs {
		ctx.SetTLSExtServernameCallback(func(ssl *SSL) (result SSLTLSExtErr) {
			defer func() {
				if recover() != nil {
					result = SSLTLSExtErrAlertFatal
				}
			}()
			serverName := normalizeSNI(ssl.GetServername())
			if serverName == "" {
				return SSLTLSExtErrNoAck
			}
			selected := r.Lookup(serverName)
			if selected == nil {
				return SSLTLSExtErrNoAck
			}
			ssl.SetSSLCtx(selected)
			return SSLTLSExtErrOK
		})
	}
}

// SNILookup resolves name in byName with wildcard fallback: "*.example.com"
// matches "a.example.com" but not deeper names such as "a.b.example.com",
// matching the single-label wildcard semantics of crypto/tls.
func SNILookup[T any](byName map[string]T, name string) (T, bool) {
	if value, ok := byName[name]; ok {
		return value, true
	}
	if dot := strings.IndexByte(name, '.'); dot > 0 {
		value, ok := byName["*"+name[dot:]]
		return value, ok
	}
	var zero T
	return zero, false
}
