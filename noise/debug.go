//go:build !js

package noise

import "github.com/ORBTR/aether"

var dbgHandshake = aether.NewDebugLogger("mesh.vl1.handshake")
var dbgKeys = aether.NewDebugLogger("mesh.vl1.noise.keys")
var dbgNoise = aether.NewDebugLogger("mesh.vl1.noise")
var dbgRelayHandler = aether.NewDebugLogger("mesh.vl1.noise.relay")
var dbgSession = aether.NewDebugLogger("mesh.vl1.noise.session")
