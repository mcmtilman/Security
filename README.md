# Security

## Authentication

### One time password

#### HOTP

HOTP implements the basic algorithm to generate a one time password according to [RFC 4226](https://tools.ietf.org/html/rfc4226), using *dynamic truncation*.

Supported *hashing algorithms* are:
* SHA1
* SHA256 (default)
* SHA384
* SHA512.

The algorithm supports a *number of (code) digits* in the range 1 ... 9.

WHOTP extends the basic HOTP functionality with the concept of *window-based validation*: a password is valid for a given counter if the counter's password or a password for any counter sufficiently close to given counter matches.

WHOTP supports a *window* in the range 1 ... 5. WHOTP validation checks counters in the range counter - window ... counter + window, starting at the center of the interval and progressively moving towards the endpoints of the interval.
