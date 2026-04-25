# Changelog

## [0.0.2](https://github.com/ORBTR/Aether/compare/v0.0.1...v0.0.2) (2026-04-25)


### Features

* browser-transport architecture — relay session pair, dial conn, grant debouncer (v0.0.12) ([77942c2](https://github.com/ORBTR/Aether/commit/77942c27a705c3a935420c850333fcb7559ed0f2))
* **grant:** env-tunable debouncer + watchdog + aether.flow.debouncer debug (v0.0.13) ([7d6e74b](https://github.com/ORBTR/Aether/commit/7d6e74bc857eed79d4279d94bd3ff33a9e21fa31))
* **memory:** bounded buffers across adapter/reliability/flow + shared watchdog (v0.0.14) ([be9f971](https://github.com/ORBTR/Aether/commit/be9f971f5425670de769f36d3bf12475431e3892))
* observability + correctness additions (v0.0.11) ([93a0419](https://github.com/ORBTR/Aether/commit/93a0419ba6b898bbcfe3e4fb0d47c939c0b78669))
* **resume:** add Store.List() for boot-time reconnect seeding ([7db3fe5](https://github.com/ORBTR/Aether/commit/7db3fe5a257eac94f40ba98423de364b87fa31d7))
* three-trigger intelligent WINDOW_UPDATE emission + receiver-driven CONGESTION ([f81584b](https://github.com/ORBTR/Aether/commit/f81584b213bf17afa9ff59bbfc5a5472ab2c2746))


### Bug Fixes

* **flow:** release unsent credit when downstream Send fails (v0.0.16) ([136ebcf](https://github.com/ORBTR/Aether/commit/136ebcf9f129f6b79d380ad515ac74a362065f0b))
* memory leaks + session-level stuck-stream detector with grade-based fallback ([132767a](https://github.com/ORBTR/Aether/commit/132767a65e7c7b48820c6a3173eca715748799cf))
