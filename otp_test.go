package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"testing"
	"time"
)

func TestHOTPCode(t *testing.T) {
	var tests = []struct {
		Value int64
		Code  int
	}{
		{1, 293240},
		{5, 932068},
		{10000, 50548},
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("2SH3V3GDW7ZNMGYE")
	if err != nil {
		t.Fatalf("failed to decode key: %v", err)
	}

	for _, test := range tests {
		c := HOTPCode(sha1.New, secret, SixDigits, test.Value)

		if c != test.Code {
			t.Errorf("Code did not match for %d. Expected %d but got %d\n", test.Value, test.Code, c)
		}
	}
}

func TestRFC4226(t *testing.T) {
	var tests = []struct {
		Value int64
		Code  int
	}{
		{0, 755224},
		{1, 287082},
		{2, 359152},
		{3, 969429},
		{4, 338314},
		{5, 254676},
		{6, 287922},
		{7, 162583},
		{8, 399871},
		{9, 520489},
	}

	for _, test := range tests {
		c := HOTPCode(sha1.New, []byte("12345678901234567890"), SixDigits, test.Value)

		if c != test.Code {
			t.Errorf("Code did not match for %d. Expected %d but got %d\n", test.Value, test.Code, c)
		}
	}
}

func TestRFC6238(t *testing.T) {
	sha1Key := []byte("12345678901234567890")
	sha256Key := []byte("12345678901234567890123456789012")
	sha512Key := []byte("1234567890123456789012345678901234567890123456789012345678901234")

	tests := []struct {
		Name         string
		Time         time.Time
		HashProvider func() hash.Hash
		Key          []byte
		Code         int
		T            int
	}{
		{"59 SHA1", time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC), sha1.New, sha1Key, 94287082, 1},
		{"59 SHA256", time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC), sha256.New, sha256Key, 46119246, 1},
		{"59 SHA512", time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC), sha512.New, sha512Key, 90693936, 1},
		{"1111111109 SHA1", time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC), sha1.New, sha1Key, 7081804, 0x23523EC},
		{"1111111109 SHA256", time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC), sha256.New, sha256Key, 68084774, 0x23523EC},
		{"1111111109 SHA512", time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC), sha512.New, sha512Key, 25091201, 0x23523EC},
		{"1111111111 SHA1", time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC), sha1.New, sha1Key, 14050471, 0x23523ED},
		{"1111111111 SHA256", time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC), sha256.New, sha256Key, 67062674, 0x23523ED},
		{"1111111111 SHA512", time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC), sha512.New, sha512Key, 99943326, 0x23523ED},
		{"1234567890 SHA1", time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC), sha1.New, sha1Key, 89005924, 0x273EF07},
		{"1234567890 SHA256", time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC), sha256.New, sha256Key, 91819424, 0x273EF07},
		{"1234567890 SHA512", time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC), sha512.New, sha512Key, 93441116, 0x273EF07},
		{"2000000000 SHA1", time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC), sha1.New, sha1Key, 69279037, 0x3F940AA},
		{"2000000000 SHA256", time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC), sha256.New, sha256Key, 90698825, 0x3F940AA},
		{"2000000000 SHA512", time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC), sha512.New, sha512Key, 38618901, 0x3F940AA},
		{"20000000000 SHA1", time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), sha1.New, sha1Key, 65353130, 0x27BC86AA},
		{"20000000000 SHA256", time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), sha256.New, sha256Key, 77737706, 0x27BC86AA},
		{"20000000000 SHA512", time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), sha512.New, sha512Key, 47863826, 0x27BC86AA},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			validator := &TOTPValidator{
				Key:          test.Key,
				HashProvider: test.HashProvider,
				Digits:       EightDigits,
			}

			ok, tMatch := validator.ValidateTOTPCode(test.Time, test.Code)
			if !ok {
				t.Error("Code did not match")
			}
			if tMatch != test.T {
				t.Errorf("T did not match. Expected %d and got %d.\n", test.T, tMatch)
			}

			code := TOTPCode(test.HashProvider, test.Key, EightDigits, 30, test.Time)
			if code != test.Code {
				t.Errorf("Code did not match. Expected %d and got %d.\n", test.Code, code)
			}
		})
	}
}

func TestTOTPValidator(t *testing.T) {
	tests := []struct {
		Name            string
		Code            int
		Match           bool
		T               int
		LastT           int
		PastTolerance   int
		FutureTolerance int
	}{
		{"T-1 Match No Window", 89731029, false, 0x23523EC, 0, 0, 0},
		{"T No Match No Window", 7081803, false, 0x23523EC, 0, 0, 0},
		{"T Match No Window", 7081804, true, 0x23523EC, 0, 0, 0},
		{"T+1 Match No Window", 14050471, false, 0x23523EC, 0, 0, 0},
		{"T-2 Match 1 Window", 48150727, false, 0x23523EC, 0, -30, 0},
		{"T-1 Match 1 Window", 89731029, true, 0x23523EB, 0, -30, 0},
		{"T-1 Match .5 Window", 89731029, false, 0x23523EC, 0, -15, 0},
		{"T Match 1 Window", 7081804, true, 0x23523EC, 0, -30, 30},
		{"T+1 Match .5 Window", 14050471, true, 0x23523ED, 0, 0, 30},
		{"T+1 Match 1 Window", 14050471, true, 0x23523ED, 0, 0, 30},
		{"T+2 Match 1 Window", 44266759, false, 0x23523EC, 0, 0, 30},
		{"T+2 Match 1.5 Window", 44266759, true, 0x23523EE, 0, 0, 45},
		{"T-1 Match 1 Window LastT", 89731029, false, 0x23523EC, 0x23523EC, -30, 30},
		{"T Match 1 Window LastT", 7081804, false, 0x23523EC, 0x23523EC, -30, 30},
		{"T+1 Match 1 Window LastT", 14050471, true, 0x23523ED, 0x23523EC, -30, 30},
		{"T+1 Match 1 Window LastT Max", 14050471, false, 0x23523EC, 0x23523EE, -30, 30},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			validator := &TOTPValidator{
				Key:             []byte("12345678901234567890"),
				HashProvider:    sha1.New,
				Digits:          EightDigits,
				PastTolerance:   time.Duration(test.PastTolerance) * -1 * time.Second,
				FutureTolerance: time.Duration(test.FutureTolerance) * time.Second,
				LastT:           test.LastT,
			}

			testTime := time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC)

			match, tMatch := validator.ValidateTOTPCode(testTime, test.Code)
			if match != test.Match {
				t.Errorf("Match did not match. Expected %t and got %t.\n", test.Match, match)
			}
			if tMatch != test.T {
				t.Errorf("T did not match. Expected %d and got %d.\n", test.T, tMatch)
			}
		})
	}
}

func Example() {
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
}
