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

By default, HOTP uses a zero *window*, i.e. when validating a counter / password combination, the password must match that specific counter. A non-zero window allows password validation to succeed if the password matches a counter sufficiently close to the specified counter by checking counters in the range `counter - window ... counter + window`. HOTP supports a window in the range `0 ... 5`.

#### TOTP

TOTP implements [RFC 6238](https://tools.ietf.org/html/rfc6238) 

The TOTP algorithm extends HOTP with the functionality to convert dates into counters and to configure this conversion process. The counter is calculated as the date's timeinterval in seconds since 00:00:00 UTC on 01/01/1970 divided by the *period*. Thus all dates in the same period yield the same password.

The algorithm supports a *period* in the range `1 ... 120` seconds, with a default of 30 seconds.

The supported *hashing algorithms* are the same as for HOTP:
* SHA1
* SHA256
* SHA384 
* SHA512.

Note that RFC 6238 mentions SHA256 and SHA512, but not SHA384.


# Requirements

The code has been tested with the Swift 5.1 Snapshot 2019-06-28 toolchain in XCode 11.6 and with the XCode 11.6 toolchain.
