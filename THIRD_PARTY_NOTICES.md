# Third-party notices

## Longfellow ZK

`marty-zkp/vendor/longfellow-zk` contains source from Google's
[Longfellow ZK](https://github.com/google/longfellow-zk) project. It is
distributed under the Apache License 2.0. The upstream license text is retained
at `marty-zkp/vendor/longfellow-zk/LICENSE`.

The vendored copy makes the published `marty-zkp` crate reproducible without a
sibling repository checkout. Upstream changes must be reviewed and imported
deliberately, with the source revision recorded in the release notes.

## linked-data

Marty resolves `linked-data` 0.1.2 from the exact reviewed commit
`6f86efc1579033e14ff2ad7d115ca0857e16a67f`. The source retains the complete
history and the `MIT/Apache-2.0` license declaration from
[`spruceid/linked-data-rs`](https://github.com/spruceid/linked-data-rs). ElevenID
hosts that immutable history on the dedicated
`deps/linked-data-rs-v0.1.2-hardening` ref in its existing SSI maintenance
repository; the source is not vendored into Marty.
