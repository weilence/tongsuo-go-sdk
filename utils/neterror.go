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

package utils

import (
	"errors"
	"net"
)

// NetError preserves net.Error semantics on wrapped errors. Consumers such as
// net/http detect expected socket timeouts by type-asserting errors directly
// to net.Error (not via errors.As), so fmt.Errorf wrapping would turn the
// expected timeout from an aborted background read into an apparent
// connection failure and cancel the in-flight request context.
type NetError struct {
	err error
}

// WrapNetError wraps err so it keeps implementing net.Error when the wrapped
// chain contains one. Errors without a net.Error in their chain are returned
// unchanged, and nil returns nil.
func WrapNetError(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return NetError{err}
	}
	return err
}

func (e NetError) Error() string { return e.err.Error() }

func (e NetError) Unwrap() error { return e.err }

func (e NetError) Timeout() bool {
	var ne net.Error
	if errors.As(e.err, &ne) {
		return ne.Timeout()
	}
	return false
}

func (e NetError) Temporary() bool {
	var ne net.Error
	if errors.As(e.err, &ne) {
		return ne.Temporary()
	}
	return false
}
