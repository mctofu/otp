# otp

An implementation TOTP [RFC 6238](http://tools.ietf.org/html/rfc6238) and HOTP [RFC 4226](http://tools.ietf.org/html/rfc4226) in go.

## Usage

```
now := time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC)
key := []byte("12345678901234567890")
stepSizeSeconds := DefaultStepSizeSeconds

code := TOTPCode(sha1.New, key, SixDigits, stepSizeSeconds, now)
fmt.Printf("TOTP code is: %06d\n", code)
// Output: TOTP code is: 081804

validator := TOTPValidator{
    Key:             key,
    PastTolerance:   DefaultStepSizeSeconds * time.Second,
    FutureTolerance: DefaultStepSizeSeconds * time.Second,
}

ok, lastT := validator.ValidateTOTPCode(now, code)
fmt.Printf("Valid: %t\n", ok)
// Valid: true

validator.LastT = lastT

ok, lastT = validator.ValidateTOTPCode(now, code)
fmt.Printf("Reuse Valid: %t\n", ok)
// Reuse Valid: false
```