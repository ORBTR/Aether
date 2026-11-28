# Changelog

## [0.1.0](https://github.com/ORBTR/Aether/compare/v0.0.118...v0.1.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* rpc/client (Client, NewClient, RPCResponse) is removed.

### Features

* the rpc/client package is removed ([8705ea8](https://github.com/ORBTR/Aether/commit/8705ea8a9e9ac8fb21d7d55393e215d7190d20c4))


### Bug Fixes

* dropped errors are handled or discarded where the code says why, and the tests check every error ([d08c3b3](https://github.com/ORBTR/Aether/commit/d08c3b3071b749bda4155bd68c6070e60b1a84c8))
* the js/wasm build finds closeAbandoned, which lives beside noiseConn in a file every build carries ([0fc5ae2](https://github.com/ORBTR/Aether/commit/0fc5ae20d2afc3fb16c5c8ff1a96491eef6e317e))
