# eris-rs

rust implementation of the *Encoding for Robust Immutable Storage* (ERIS) [spec draft](https://eris.codeberg.page/spec/).

Like the spec, this library does not implement storage backends or networking.

# State

The library implements the spec in version 0.3.0 and successfully passes all test vectors
and test streams generated through `ChaCha20` (see "5.2. Large content" in spec).

# Notes

When running the tests, make sure to use `release` builds as the performance will increase
by a factor of 100 (!):

```
cargo test --release
```

# TODOs

* add some benches
* improve performance
* publish on crates.io

# Copyright & License

Copyright (c) 2022 Maximilian Günter <code@sourcediver.org>

This rust implementation of `ERIS` is licensed under the AGPLv3 unless noted otherwise.
See LICENSE for the full license text.
