package scanner

import (
	"fmt"
	"regexp"
	"strconv"
)

// Supported Kingfisher version range. The JSON parser is non-strict
// (DisallowUnknownFields is OFF), so newer kingfisher versions that add
// fields don't break parsing. SPEC §17.2 bumps the range in lockstep with
// kingfisher releases; the upper bound is set to leave headroom.
const (
	MinSupportedKingfisher = "0.6.0"
	MaxSupportedKingfisher = "2.0.0" // exclusive upper bound
)

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// CheckKingfisherVersion compares observed against [Min, Max) inclusive of Min.
// Returns (supported, parseErr). Out-of-range is not an error — caller decides.
func CheckKingfisherVersion(observed string) (supported bool, err error) {
	o, err := parseSemver(observed)
	if err != nil {
		return false, fmt.Errorf("parse observed %q: %w", observed, err)
	}
	low, _ := parseSemver(MinSupportedKingfisher)
	high, _ := parseSemver(MaxSupportedKingfisher)
	if cmpSemver(o, low) < 0 || cmpSemver(o, high) >= 0 {
		return false, nil
	}
	return true, nil
}

type semver struct{ Major, Minor, Patch int }

func parseSemver(s string) (semver, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return semver{}, fmt.Errorf("not a semver-like string")
	}
	maj, _ := strconv.Atoi(m[1])
	mnr, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return semver{maj, mnr, pat}, nil
}

func cmpSemver(a, b semver) int {
	if a.Major != b.Major {
		return a.Major - b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor - b.Minor
	}
	return a.Patch - b.Patch
}
