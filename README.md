# Security

## Authentication

### One time password

#### HOTP

HOTP implements the basic algorithm to generate a one time password according to [RFC4226](https://tools.ietf.org/html/rfc4226), using *dynamic truncation*.

Supported *hashing algorithms* are:
* SHA1
* SHA256 (default)
* SHA384
* SHA512.

The algorithm supports a *number of (code) digits* in the range 1 ... 9.

WHOTP extends the basic HOTP functionality with the concept of *window-based validation*, where a range of counters centered around a given counter is used to determince if a password is deemed acceptable for the given counter.
