# Security

## Authentication

### One time password

#### HOTP

HOTP implements the basic algorithm to generate and validate a one time password according to [RFC 4226](https://tools.ietf.org/html/rfc4226).

Supported *hashing algorithms* are:
* SHA1 (default)
* SHA256
* SHA384 
* SHA512.

Note that RFC 4226 only mentions SHA1 hashing.

The algorithm supports a *number of (code) digits* in the range `1 ... 9`.

By default, HOTP uses *dynamic truncation offsets*. This behavior can be overridden by an *explicit truncation offset* in the range `0 ..< algorithm.byteCount - 4`.

By default, HOTP uses no *window*, i.e. when validating a counter / password combination, the match must be exact. A window allows password validation to succeed if the password matches a counter sufficiently close to the specified counter. HOTP supports a window in the range `1 ... 5`. HOTP validation checks counters in the range `counter - window ... counter + window`.

#### TOTP

TOTP implements [RFC 6238](https://tools.ietf.org/html/rfc6238) 

Supported *hashing algorithms* are:
* SHA1 (default)
* SHA256
* SHA384 
* SHA512.

Note that RFC 6238 mentions SHA256 and SHA512, but not SHA384.
