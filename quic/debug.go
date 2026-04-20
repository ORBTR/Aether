//go:build !js

package quic

import "github.com/ORBTR/aether"

var dbgQUIC = aether.NewDebugLogger("mesh.aether.quic")
var dbgSession = aether.NewDebugLogger("mesh.aether.quic.session")
