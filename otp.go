package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"time"
)

// Digits configures the number of digits returned in a HOTP code
type Digits uint32

// Common Digits configurations
const (
	SixDigits   Digits = 1000000
	SevenDigits        = SixDigits * 10
	EightDigits        = SevenDigits * 10
)

// Defaults
const (
	DefaultStepSizeSeconds = 30
)

// HOTPCode generates a HMAC-Based One-Time Password from value as described in RFC 4226.
// Common parameters are sha1 hash, 20 byte shared key and SixDigits output.
func HOTPCode(hashProvider func() hash.Hash, key []byte, digits Digits, value int64) int {
	h := hmac.New(hashProvider, key)
	if err := binary.Write(h, binary.BigEndian, value); err != nil {
		// this should not ever happen
		panic(err)
	}

	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	snip := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return int(snip % uint32(digits))
}

// TOTPCode generates a Time-Based One-Time Password from a time as described in RFC 6238.
// Common parameters are sha1 hash, 20 byte shared key, SixDigits output and a 30 second step size.
func TOTPCode(hashProvider func() hash.Hash, key []byte, digits Digits, stepSizeSeconds int, t time.Time) int {
	return HOTPCode(hashProvider, key, digits, int64(timeSteps(stepSizeSeconds, t)))
}

// TOTPValidator assists in validating a provided TOTP code.
// Past and Future tolerance establish a range of time that codes will be accepted for.
// LastT will restrict code acceptance to time steps after LastT.
type TOTPValidator struct {
	Key             []byte
	StepSizeSeconds int
	PastTolerance   time.Duration // expected to be positive
	FutureTolerance time.Duration
	LastT           int
	HashProvider    func() hash.Hash
	Digits          Digits
}

// ValidateTOTPCode returns a bool indicating if code is valid for the provided time.
// It also returns a value T which can be set to TOTPValidator.LastT to prevent a valid
// code from being reused.
func (tc *TOTPValidator) ValidateTOTPCode(now time.Time, code int) (bool, int) {
	hashProvider := tc.HashProvider
	if hashProvider == nil {
		hashProvider = sha1.New
	}

	digits := tc.Digits
	if digits == 0 {
		digits = SixDigits
	}

	stepSizeSeconds := tc.StepSizeSeconds
	if stepSizeSeconds == 0 {
		stepSizeSeconds = DefaultStepSizeSeconds
	}

	tMin := timeSteps(stepSizeSeconds, now.Add(-tc.PastTolerance))
	tMax := timeSteps(stepSizeSeconds, now.Add(tc.FutureTolerance))
	for t := tMin; t <= tMax; t++ {
		if t <= tc.LastT {
			continue
		}

		if HOTPCode(hashProvider, tc.Key, digits, int64(t)) == code {
			return true, t
		}
	}

	return false, timeSteps(stepSizeSeconds, now)
}

func timeSteps(stepSize int, t time.Time) int {
	return int(t.Unix() / int64(stepSize))
}
