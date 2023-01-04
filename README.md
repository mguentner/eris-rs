# eris-rs

[![Pipeline](https://github.com/mguentner/eris-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/mguentner/eris-rs/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/eris-rs.svg)](https://crates.io/crates/eris-rs)

rust implementation of the *Encoding for Robust Immutable Storage* (ERIS) [spec](https://eris.codeberg.page/spec/).

Like the spec, this library does not implement storage backends or networking.

# State

The library implements the spec in version 1.0.0 and successfully passes all test vectors
and test streams generated through `ChaCha20` (see "5.2. Large content" in spec).

# Notes

When running the tests, make sure to use `release` builds as the performance will increase
by a factor of 100 (!):

```
cargo test --release
```

# Copyright & License

Copyright (c) 2023 Maximilian Günter <code@sourcediver.org>

This rust implementation of `ERIS` is licensed under the AGPLv3 unless noted otherwise.
See LICENSE for the full license text.