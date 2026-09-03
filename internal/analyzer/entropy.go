package analyzer

import (
	"math"
	"strings"
	"unicode"
)

// AlphabetType identifies the character set classification of a candidate secret.
type AlphabetType string

const (
	AlphabetHex           AlphabetType = "hexadecimal"
	AlphabetBase64        AlphabetType = "base64"
	AlphabetAlphaNumPunct AlphabetType = "alphanumeric_punctuation"
	AlphabetUnknown       AlphabetType = "unknown"
)

// EntropyThresholds defines minimal lengths and entropy cutoffs for each character set.
const (
	MinLengthHex   = 32
	ThresholdHex   = 3.0

	MinLengthBase64 = 20
	ThresholdBase64 = 4.5

	MinLengthPunct = 16
	ThresholdPunct = 4.7
)

// CalculateShannonEntropy computes Shannon entropy H(X) = -sum(P(x_i) * log2(P(x_i)))
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	charCounts := make(map[rune]int, 64)
	for _, r := range s {
		charCounts[r]++
	}

	strLen := float64(len(s))
	var entropy float64
	for _, count := range charCounts {
		p := float64(count) / strLen
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// DetectAlphabet classifies the character distribution of a token string.
func DetectAlphabet(s string) AlphabetType {
	if len(s) == 0 {
		return AlphabetUnknown
	}

	isHex := true
	isBase64 := true

	for _, r := range s {
		if !isHexRune(r) {
			isHex = false
		}
		if !isBase64Rune(r) {
			isBase64 = false
		}
	}

	if isHex {
		return AlphabetHex
	}
	if isBase64 {
		return AlphabetBase64
	}
	return AlphabetAlphaNumPunct
}

// MeetsEntropyThreshold evaluates if candidate meets minimum length and entropy for its alphabet.
func MeetsEntropyThreshold(s string) (bool, AlphabetType, float64) {
	alphabet := DetectAlphabet(s)
	entropy := CalculateShannonEntropy(s)
	length := len(s)

	switch alphabet {
	case AlphabetHex:
		if length >= MinLengthHex && entropy >= ThresholdHex {
			// Specific mitigation: 40-character hex string is typical Git commit SHA
			// Git commit SHAs rarely exceed 3.9 entropy unless truly random high-entropy key
			if length == 40 && entropy < 3.95 {
				return false, alphabet, entropy
			}
			return true, alphabet, entropy
		}
	case AlphabetBase64:
		if length >= MinLengthBase64 && entropy >= ThresholdBase64 {
			return true, alphabet, entropy
		}
	case AlphabetAlphaNumPunct:
		if length >= MinLengthPunct && entropy >= ThresholdPunct {
			return true, alphabet, entropy
		}
	}

	return false, alphabet, entropy
}

// HasLowVarianceOrSequential checks for repeating or predictable sequences (e.g., "123456789", "aaaaaa").
func HasLowVarianceOrSequential(s string) bool {
	if len(s) < 4 {
		return true
	}

	uniqueRunes := make(map[rune]struct{}, 16)
	for _, r := range s {
		uniqueRunes[r] = struct{}{}
	}

	// If fewer than 4 unique runes in a long candidate, it's low variance repetition
	if len(uniqueRunes) < 4 {
		return true
	}

	// Check for repeating chunks of length 2 to 10 (e.g. "012345678901234567890123456789" or "abcabcabc")
	for chunkSize := 2; chunkSize <= 10 && chunkSize*2 <= len(s); chunkSize++ {
		pattern := s[:chunkSize]
		repeated := strings.Repeat(pattern, len(s)/chunkSize)
		remainder := len(s) % chunkSize
		if repeated+pattern[:remainder] == s {
			return true
		}
	}

	// Check for sequential runs of ASCII characters (increasing or decreasing)
	seqCount := 1
	maxSeq := 1
	runes := []rune(s)
	for i := 1; i < len(runes); i++ {
		diff := runes[i] - runes[i-1]
		if diff == 1 || diff == -1 {
			seqCount++
			if seqCount > maxSeq {
				maxSeq = seqCount
			}
		} else {
			seqCount = 1
		}
	}

	// If more than 50% of the string is a single monotonic sequence, discard it
	if float64(maxSeq)/float64(len(runes)) > 0.5 {
		return true
	}

	return false
}

func isHexRune(r rune) bool {
	return (r >= '0' && r <= '9') ||
		(r >= 'a' && r <= 'f') ||
		(r >= 'A' && r <= 'F')
}

func isBase64Rune(r rune) bool {
	return unicode.IsLetter(r) ||
		unicode.IsDigit(r) ||
		r == '+' || r == '/' || r == '='
}

// CleanToken removes surrounding quotes, whitespace, and semicolons from parsed string literals.
func CleanToken(s string) string {
	cutset := " \t\r\n\"'`<>;,(){}[]"
	prev := ""
	for prev != s {
		prev = s
		s = strings.Trim(s, cutset)
	}
	return s
}
