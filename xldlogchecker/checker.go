// Package xldlogchecker implements verification of X Lossless Decoder (XLD)
// log file signatures.
//
// XLD embeds a cryptographic signature at the end of every log file using:
//  1. SHA-256 with a non-standard initial state (custom IV)
//  2. A proprietary scrambling function that operates on 8-byte pairs
//  3. A non-standard base64 encoding with a custom 64-character alphabet
//
// # Usage as a library
//
//	result := xldlogchecker.ParseLog("path/to/file.log")
//	switch result.Status {
//	case "OK":  // signature valid
//	case "BAD": // signature present but wrong (Malformed / Forged)
//	case "ERROR": // file not found or not an XLD log
//	}
//
// For in-memory content use [VerifyContent].
package xldlogchecker

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// logcheckerMinVersion is the minimum XLD version whose logs are considered
// legitimate. Logs produced by XLD <= this version string are flagged as Forged.
// The comparison is lexicographic, which is equivalent to chronological for the
// YYYYMMDD version format used by XLD.
const logcheckerMinVersion = "20121027"

// xldEncoding is the non-standard base64 encoding used by XLD.
// It uses the alphabet  0-9 A-Z a-z . _  (no padding) instead of the
// standard  A-Z a-z 0-9 + /  alphabet.
var xldEncoding = base64.NewEncoding(
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._",
).WithPadding(base64.NoPadding)

// Result holds the outcome of checking an XLD log file.
// The JSON tags match the original Python xld_logchecker output exactly so
// that downstream consumers do not need changes.
type Result struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

// ---- bit-rotation helpers ----

func rotL(n, k uint32) uint32 { return (n << k) | (n >> (32 - k)) }
func rotR(n, k uint32) uint32 { return rotL(n, 32-k) }

// sha256XLD computes SHA-256 over data using a non-standard initial state and
// returns the lowercase hex-encoded digest (64 characters).
//
// Only the initial state (IV) differs from standard SHA-256; the padding and
// round constants are identical to FIPS 180-4.
func sha256XLD(data []byte) string {
	state := [8]uint32{
		0x1D95E3A4, 0x06520EF5, 0x3A9CFB75, 0x6104BCAE,
		0x09CEDA82, 0xBA55E60B, 0xEAEC16C6, 0xEB19AF15,
	}

	// Standard SHA-256 round constants (FIPS 180-4).
	rc := [64]uint32{
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
	}

	// ---- Message padding (FIPS 180-4 §5.1.1) ----
	// L = message length in bits.
	L := uint64(len(data)) * 8

	// Find the smallest K >= 0 such that (L + 1 + K + 64) % 512 == 0.
	// K is in bits; the Python implementation iterates from 0 to 511.
	bitK := 0
	for (L+1+uint64(bitK)+64)%512 != 0 {
		bitK++
	}

	// Append: 0x80 byte (the mandatory 1-bit + 7 zero-bits),
	//         (bitK-7)/8 additional zero bytes,
	//         8-byte big-endian representation of L.
	data = append(data, 0x80)
	data = append(data, make([]byte, (bitK-7)/8)...)
	var lb [8]byte
	binary.BigEndian.PutUint64(lb[:], L)
	data = append(data, lb[:]...)

	// ---- Process 64-byte (512-bit) chunks ----
	for start := 0; start < len(data); start += 64 {
		chunk := data[start : start+64]

		// Build the 64-word message schedule.
		var w [64]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(chunk[i*4 : i*4+4])
		}
		for i := 16; i < 64; i++ {
			s0 := rotR(w[i-15], 7) ^ rotR(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 := rotR(w[i-2], 17) ^ rotR(w[i-2], 19) ^ (w[i-2] >> 10)
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		a, b, c, d, e, f, g, h :=
			state[0], state[1], state[2], state[3],
			state[4], state[5], state[6], state[7]

		for i := 0; i < 64; i++ {
			s0 := rotR(a, 2) ^ rotR(a, 13) ^ rotR(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := s0 + maj

			s1 := rotR(e, 6) ^ rotR(e, 11) ^ rotR(e, 25)
			ch := (e & f) ^ (^e & g) // ^e is 32-bit bitwise NOT (uint32)
			t1 := h + s1 + ch + rc[i] + w[i]

			h = g; g = f; f = e
			e = d + t1
			d = c; c = b; b = a
			a = t1 + t2
		}

		state[0] += a; state[1] += b; state[2] += c; state[3] += d
		state[4] += e; state[5] += f; state[6] += g; state[7] += h
	}

	return fmt.Sprintf("%08x%08x%08x%08x%08x%08x%08x%08x",
		state[0], state[1], state[2], state[3],
		state[4], state[5], state[6], state[7])
}

// scramble applies the XLD proprietary scrambling function to data.
//
// The function operates on 8-byte pairs using two 32-bit accumulators (X, Y)
// and a set of magic constants. When the data length is not a multiple of 8,
// the final partial chunk is XOR-encrypted rather than fully scrambled.
func scramble(data []byte) []byte {
	mc := [8]uint32{
		0x99036946, 0xE99DB8E7, 0xE3AE2FA7, 0x0A339740,
		0xF06EB6A9, 0x92FF9B65, 0x028F7873, 0x9070E316,
	}

	// Split off any unaligned trailing bytes.
	var unaligned []byte
	if len(data)%8 != 0 {
		stop := 8 * (len(data) / 8)
		unaligned = make([]byte, len(data)-stop)
		copy(unaligned, data[stop:])
		// Replace the tail with 8 zero bytes so the loop has a full last block.
		padded := make([]byte, stop+8)
		copy(padded, data[:stop])
		data = padded
	}

	X := uint32(0x6479B873)
	Y := uint32(0x48853AFC)

	output := make([]byte, 0, len(data))

	for offset := 0; offset < len(data); offset += 8 {
		X ^= binary.BigEndian.Uint32(data[offset : offset+4])
		Y ^= binary.BigEndian.Uint32(data[offset+4 : offset+8])

		for r := 0; r < 4; r++ {
			for i := 0; i < 2; i++ {
				Y ^= X

				a := mc[4*i+0] + Y
				b := a - 1 + rotL(a, 1)
				X ^= b ^ rotL(b, 4)

				c := mc[4*i+1] + X
				d := c + 1 + rotL(c, 2)
				e := mc[4*i+2] + (d ^ rotL(d, 8))
				f := rotL(e, 1) - e
				Y ^= (X | f) ^ rotL(f, 16)

				g := mc[4*i+3] + Y
				X ^= g + 1 + rotL(g, 2)
			}
		}

		var block [8]byte
		binary.BigEndian.PutUint32(block[:4], X)
		binary.BigEndian.PutUint32(block[4:], Y)
		output = append(output, block[:]...)
	}

	// Handle unaligned trailing chunk: XOR the last scrambled block with
	// the unaligned bytes, keeping only len(unaligned) output bytes.
	if len(unaligned) > 0 {
		lastStart := len(output) - 8
		result := make([]byte, len(unaligned))
		for i, b := range unaligned {
			result[i] = output[lastStart+i] ^ b
		}
		output = append(output[:lastStart], result...)
	}

	return output
}

// extractInfo parses an XLD log string into its unsigned body, XLD version
// string, and the embedded signature.
//
// version is empty when the first line does not start with
// "X Lossless Decoder version".
// signature is empty when no BEGIN/END XLD SIGNATURE block is found.
func extractInfo(data string) (body, version, signature string) {
	// Determine the version from the first line (strip any trailing \r).
	firstLine := strings.SplitN(data, "\n", 2)[0]
	firstLine = strings.TrimRight(firstLine, "\r")
	if strings.HasPrefix(firstLine, "X Lossless Decoder version") {
		if fields := strings.Fields(firstLine); len(fields) >= 5 {
			version = fields[4]
		}
	}

	// Locate and strip the signature block.
	const beginMarker = "\n-----BEGIN XLD SIGNATURE-----\n"
	const endMarker = "\n-----END XLD SIGNATURE-----\n"

	if idx := strings.Index(data, beginMarker); idx != -1 {
		body = data[:idx]
		rest := data[idx+len(beginMarker):]
		if endIdx := strings.Index(rest, endMarker); endIdx != -1 {
			signature = strings.TrimSpace(rest[:endIdx])
		} else {
			signature = strings.TrimSpace(rest)
		}
	} else {
		body = data // no signature block found; signature stays ""
	}

	return
}

// xldVerify extracts the unsigned body from text, computes the expected XLD
// signature, and returns (body, version, embeddedSig, computedSig).
func xldVerify(text string) (body, version, oldSig, newSig string) {
	body, version, oldSig = extractInfo(text)

	// Compute SHA-256 (custom IV) over the UTF-8-encoded unsigned body.
	digest := sha256XLD([]byte(body))

	// XLD appends a fixed version tag to the hex digest before scrambling.
	payload := []byte(digest + "\nVersion=0001")

	// Scramble then encode with the non-standard base64 (no padding).
	newSig = xldEncoding.EncodeToString(scramble(payload))

	return
}

// ParseLog reads the XLD log at path and returns a [Result] describing the
// file's integrity.
//
// Possible statuses:
//   - "OK"    — embedded signature matches the computed signature
//   - "BAD"   — signature is present but wrong ("Malformed") or the XLD
//     version is too old to be trusted ("Forged")
//   - "ERROR" — file could not be opened or is not a valid XLD log
func ParseLog(path string) Result {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{Message: "error: cannot open file", Status: "ERROR"}
	}

	// XLD logs are UTF-8; bail out early for binary / non-UTF-8 files.
	if !utf8.Valid(data) {
		return Result{Message: "Not a logfile", Status: "ERROR"}
	}

	return verifyString(string(data))
}

// VerifyContent verifies an XLD log provided as a string.
//
// This is convenient when the content is already in memory (e.g. fetched from
// a database or HTTP response) and avoids writing to a temporary file.
func VerifyContent(content string) Result {
	if !utf8.ValidString(content) {
		return Result{Message: "Not a logfile", Status: "ERROR"}
	}
	return verifyString(content)
}

// verifyString is the shared implementation used by [ParseLog] and
// [VerifyContent].
func verifyString(text string) Result {
	_, version, oldSig, newSig := xldVerify(text)

	switch {
	case oldSig == "":
		return Result{Message: "Not a logfile", Status: "ERROR"}
	case oldSig != newSig:
		return Result{Message: "Malformed", Status: "BAD"}
	case version <= logcheckerMinVersion:
		// Empty version string also satisfies "" <= "20121027".
		return Result{Message: "Forged", Status: "BAD"}
	default:
		return Result{Message: "OK", Status: "OK"}
	}
}
