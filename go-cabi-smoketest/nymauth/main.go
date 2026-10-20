// Command nymauth is a real cgo program that links against zk-cred-longfellow's plain C ABI
// (see `make go-cabi`, `src/nymauth/c_abi.rs` and `include/zk_cred_longfellow_nymauth.h`) and
// drives the nym_auth verifier the way a Go verifier service would: load the circuit and
// parameters once, derive the challenge from its own request, verify an honest proof, refuse
// tampered ones, and read the pseudonym.
//
// Usage:
//
//  1. make go-cabi go-cabi-nymauth-fixture
//  2. cd go-cabi-smoketest && LD_LIBRARY_PATH=../target/go-cabi go run ./nymauth
//     (or: make go-cabi-nymauth-smoke)
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../target/go-cabi -lzk_cred_longfellow
#include <stdlib.h>
#include "zk_cred_longfellow_nymauth.h"
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

type fixture struct {
	HashCircuitID     string `json:"hash_circuit_id"`
	SigCircuitID      string `json:"sig_circuit_id"`
	BlockEncHash      uint32 `json:"block_enc_hash"`
	BlockEncSig       uint32 `json:"block_enc_sig"`
	IssuerKeyX        string `json:"issuer_key_x"`
	IssuerKeyY        string `json:"issuer_key_y"`
	Time              string `json:"time"`
	Earliest          string `json:"earliest"`
	Cutoff            string `json:"cutoff"`
	Origin            string `json:"origin"`
	Nonce             string `json:"nonce"`
	DocType           string `json:"doc_type"`
	ClientID          string `json:"client_id"`
	Pseudonym         string `json:"pseudonym"`
	ChallengeDigest   string `json:"challenge_digest"`
	SessionTranscript string `json:"session_transcript"`
	VerifierInput     string `json:"verifier_input"`
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	return b
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fail("bad hex %q", s)
	}
	return b
}

// pinner keeps the Go buffers that C structs point into pinned: cgo forbids passing a struct that
// holds Go pointers unless the pointees are pinned.
var pinner runtime.Pinner

// nb views a Go byte slice as a NymAuthBytes, pinning the slice until main returns.
func nb(b []byte) C.NymAuthBytes {
	if len(b) == 0 {
		return C.NymAuthBytes{}
	}
	pinner.Pin(&b[0])
	return C.NymAuthBytes{ptr: (*C.uint8_t)(unsafe.Pointer(&b[0])), len: C.size_t(len(b))}
}

func takeError(e *C.char) string {
	if e == nil {
		return ""
	}
	s := C.GoString(e)
	C.nymauth_free_error_string(e)
	return s
}

func main() {
	defer pinner.Unpin()
	dir := "../target/go-cabi/testdata-nymauth"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	circuit := mustRead(filepath.Join(dir, "circuit.bin"))
	proof := mustRead(filepath.Join(dir, "proof.bin"))
	var fx fixture
	if err := json.Unmarshal(mustRead(filepath.Join(dir, "fixture.json")), &fx); err != nil {
		fail("fixture.json: %v", err)
	}

	hashID, sigID := []byte(fx.HashCircuitID), []byte(fx.SigCircuitID)
	params := C.NymAuthCParams{
		block_enc_hash:  C.uint32_t(fx.BlockEncHash),
		block_enc_sig:   C.uint32_t(fx.BlockEncSig),
		hash_circuit_id: nb(hashID),
		sig_circuit_id:  nb(sigID),
	}

	// 1. Load once.
	var errOut *C.char
	verifier := C.nymauth_verifier_new(nb(circuit), &params, &errOut)
	if verifier == nil {
		fail("nymauth_verifier_new: %s", takeError(errOut))
	}
	defer C.nymauth_verifier_free(verifier)
	fmt.Println("OK: nymauth_verifier_new loaded the circuit pair")

	// 2. Derive the challenge from the verifier's own request, and check it is the fixture's.
	origin, nonce, docType := []byte(fx.Origin), []byte(fx.Nonce), []byte(fx.DocType)
	var transcriptPtr *C.uint8_t
	var transcriptLen C.size_t
	var digest [32]byte
	rc := C.nymauth_derive_challenge(nb(origin), nb(nonce), nb(docType), C.NymAuthBytes{},
		&transcriptPtr, &transcriptLen, (*C.uint8_t)(unsafe.Pointer(&digest[0])), &errOut)
	if rc != 0 {
		fail("nymauth_derive_challenge: status=%d %s", rc, takeError(errOut))
	}
	transcript := C.GoBytes(unsafe.Pointer(transcriptPtr), C.int(transcriptLen))
	C.nymauth_free_buffer(transcriptPtr, transcriptLen)
	if hex.EncodeToString(transcript) != fx.SessionTranscript || hex.EncodeToString(digest[:]) != fx.ChallengeDigest {
		fail("derived challenge differs from the fixture")
	}
	var vi [32]byte
	clientID := []byte(fx.ClientID)
	if rc := C.nymauth_verifier_input(nb(clientID), (*C.uint8_t)(unsafe.Pointer(&vi[0])), &errOut); rc != 0 || hex.EncodeToString(vi[:]) != fx.VerifierInput {
		fail("verifier_input: status=%d %s", rc, takeError(errOut))
	}
	fmt.Println("OK: nymauth_derive_challenge and nymauth_verifier_input agree with the fixture")

	// 3. Verify the honest proof; the pseudonym is the one it reports.
	qx, qy := unhex(fx.IssuerKeyX), unhex(fx.IssuerKeyY)
	timeB, earliest, cutoff := []byte(fx.Time), []byte(fx.Earliest), []byte(fx.Cutoff)
	request := func(seed []byte) C.NymAuthCRequest {
		return C.NymAuthCRequest{
			issuer_key_x:     nb(qx),
			issuer_key_y:     nb(qy),
			time:             nb(timeB),
			earliest:         nb(earliest),
			cutoff:           nb(cutoff),
			challenge_digest: nb(digest[:]),
			verifier_input:   nb(vi[:]),
			transcript_seed:  nb(seed),
		}
	}
	pseudonym := unhex(fx.Pseudonym)
	req := request(transcript)
	if rc := C.nymauth_verify(verifier, &req, nb(pseudonym), nb(proof), &errOut); rc != 0 {
		fail("honest proof refused: status=%d %s", rc, takeError(errOut))
	}
	fmt.Printf("OK: honest proof verified; pseudonym %s\n", fx.Pseudonym)

	// 4. Refusals, each with a status and a message.
	expect := func(name string, want C.int32_t, rc C.int32_t, e *C.char) {
		msg := takeError(e)
		if rc != want || msg == "" {
			fail("%s: status=%d (want %d) message=%q", name, rc, want, msg)
		}
		fmt.Printf("OK: %s refused (status=%d): %s\n", name, rc, msg)
	}
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)/2] ^= 0xff
	rc = C.nymauth_verify(verifier, &req, nb(pseudonym), nb(tampered), &errOut)
	expect("tampered proof", -7, rc, errOut)

	wrong := append([]byte(nil), pseudonym...)
	wrong[0] ^= 1
	rc = C.nymauth_verify(verifier, &req, nb(wrong), nb(proof), &errOut)
	expect("another pseudonym", -7, rc, errOut)

	short := []byte("too short")
	shortReq := request(short)
	rc = C.nymauth_verify(verifier, &shortReq, nb(pseudonym), nb(proof), &errOut)
	expect("short transcript seed", -1, rc, errOut)

	// The verifier itself checks that the issuer key is a point of P-256 (the circuits do not):
	// an off-curve key is refused as invalid input before any proof work, the genuine key above
	// was accepted.
	offY := append([]byte(nil), qy...)
	offY[31] ^= 1
	offReq := req
	offReq.issuer_key_y = nb(offY)
	rc = C.nymauth_verify(verifier, &offReq, nb(pseudonym), nb(proof), &errOut)
	expect("issuer key off the curve", -1, rc, errOut)
	zeroKey := make([]byte, 32)
	zeroReq := req
	zeroReq.issuer_key_x = nb(zeroKey)
	zeroReq.issuer_key_y = nb(zeroKey)
	rc = C.nymauth_verify(verifier, &zeroReq, nb(pseudonym), nb(proof), &errOut)
	expect("issuer key (0, 0)", -1, rc, errOut)

	// 5. An unlisted circuit build fails closed at load.
	other := []byte("00" + fx.HashCircuitID[2:])
	badParams := params
	badParams.hash_circuit_id = nb(other)
	if v := C.nymauth_verifier_new(nb(circuit), &badParams, &errOut); v != nil {
		fail("an unlisted circuit id loaded")
	}
	if msg := takeError(errOut); msg == "" {
		fail("unlisted circuit refused without a message")
	} else {
		fmt.Printf("OK: unlisted circuit refused at load: %s\n", msg)
	}
	fmt.Println("ALL OK: real Go/cgo call into the nym_auth C ABI succeeded end-to-end")
}
