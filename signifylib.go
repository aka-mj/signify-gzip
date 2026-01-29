package main

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gitlab.com/michaeljohn/bcrypt_pbkdf"
	"golang.org/x/crypto/ed25519"
)

const (
	commentHdr       = "untrusted comment: "
	defaultKDFRounds = 42
)

var (
	algoEd     = [2]byte{'E', 'd'}
	algoBcrypt = [2]byte{'B', 'K'}
)

type PrivateKey struct {
	Bytes       [ed25519.PrivateKeySize]byte
	Fingerprint [8]byte
}

type PublicKey struct {
	Bytes       [ed25519.PublicKeySize]byte
	Fingerprint [8]byte
}

type Signature struct {
	Bytes       [ed25519.SignatureSize]byte
	Fingerprint [8]byte
}

type rawEncryptedKey struct {
	PKAlgo       [2]byte
	KDFAlgo      [2]byte
	KDFRounds    uint32
	Salt         [16]byte
	Checksum     [8]byte
	Fingerprint  [8]byte
	EncryptedKey [ed25519.PrivateKeySize]byte
}

type rawPublicKey struct {
	PKAlgo      [2]byte
	Fingerprint [8]byte
	PublicKey   [ed25519.PublicKeySize]byte
}

type rawSignature struct {
	PKAlgo      [2]byte
	Fingerprint [8]byte
	Signature   [ed25519.SignatureSize]byte
}

func GetSignatureFromGZipComment(comment string) (sig *Signature, err error) {
	buf := bytes.NewBufferString(comment)
	_, content, err := readFile(buf)
	if err != nil {
		return nil, err
	}

	return ParseSignature(content)
}

func ReadSecKey(filename string, passphrase []byte) (*PrivateKey, error) {
	secFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	_, con, err := readFile(secFile)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(con, passphrase)
}

func ReadPubKey(filename string) (*PublicKey, error) {
	pubFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	_, con, err := readFile(pubFile)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(con)
}

func readFile(r io.Reader) (comment string, content []byte, err error) {
	sc := bufio.NewScanner(r)

	if !sc.Scan() {
		return "", nil, fmt.Errorf("signify: read error %s", sc.Err())
	}
	comment = sc.Text()
	if !strings.HasPrefix(comment, commentHdr) {
		return "", nil, errors.New("signify: missing header")
	}
	comment = comment[len(commentHdr):]

	if !sc.Scan() {
		return "", nil, fmt.Errorf("signify: read error %s", sc.Err())
	}
	content, err = base64.StdEncoding.DecodeString(sc.Text())

	return
}

func CreateGZipComment(comment, secKey string, s *Signature) string {
	// Write gzip header comment to buffer
	commentBuf := new(bytes.Buffer)
	// write signify comment header and signature
	writeFile(commentBuf, comment, MarshalSignature(s))
	// write date and key
	fmt.Fprintf(commentBuf, "date=%s\nkey=%s\n", time.Now().Format(time.RFC3339), secKey)
	// commentBuf.WriteString(fmt.Sprintf("date=%s\nkey=%s\n", time.Now().Format(time.RFC3339), secKey))

	return commentBuf.String()
}

func WriteSecKey(key *PrivateKey, passphrase []byte, comment string) error {
	f, err := os.OpenFile(cliOpt.secKey, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	msec, err := MarshalPrivateKey(key, cryptorand.Reader, passphrase, 5)
	if err != nil {
		return err
	}

	if comment == "" {
		comment = "signify secret key"
	}
	return writeFile(f, comment, msec)
}

func WritePubKey(key *PublicKey, comment string) error {
	f, err := os.OpenFile(cliOpt.pubKey, os.O_RDWR|os.O_CREATE, 0662)
	if err != nil {
		return err
	}
	defer f.Close()

	if comment == "" {
		comment = "signify public key"
	}
	return writeFile(f, comment, MarshalPublicKey(key))
}

func writeFile(w io.Writer, comment string, content []byte) error {
	b64 := base64.StdEncoding.EncodeToString(content)
	_, err := fmt.Fprintf(w, "%s%s\n%s\n", commentHdr, comment, b64)
	return err
}

func parseRawEncryptedKey(data []byte) (*rawEncryptedKey, error) {
	var ek rawEncryptedKey
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &ek); err != nil {
		return nil, err
	}
	return &ek, nil
}

func marshalRawEncryptedKey(rek *rawEncryptedKey) []byte {
	var wbuf bytes.Buffer
	binary.Write(&wbuf, binary.BigEndian, rek)
	return wbuf.Bytes()
}

func parseRawPublicKey(data []byte) (*rawPublicKey, error) {
	var pub rawPublicKey
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

func marshalRawPublicKey(rpub *rawPublicKey) []byte {
	var wbuf bytes.Buffer
	binary.Write(&wbuf, binary.BigEndian, rpub)
	return wbuf.Bytes()
}

func parseRawSignature(data []byte) (*rawSignature, error) {
	var sig rawSignature
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

func marshalRawSignature(rsig *rawSignature) []byte {
	var wbuf bytes.Buffer
	binary.Write(&wbuf, binary.BigEndian, rsig)
	return wbuf.Bytes()
}

func decryptPrivateKey(rek *rawEncryptedKey, passphrase []byte) (*PrivateKey, error) {
	var priv PrivateKey
	var xorkey []byte
	var err error

	if rek.KDFRounds != 0 {
		xorkey, err = bcrypt_pbkdf.Key(passphrase, rek.Salt[:], int(rek.KDFRounds), ed25519.PrivateKeySize)
		if err != nil {
			return nil, err
		}
	} else {
		xorkey = make([]byte, ed25519.PrivateKeySize)
	}

	for i := range priv.Bytes {
		priv.Bytes[i] = rek.EncryptedKey[i] ^ xorkey[i]
	}

	privcs := checksum(priv.Bytes[:])
	if subtle.ConstantTimeCompare(privcs[:], rek.Checksum[:]) != 1 {
		return nil, errors.New("signify: invalid passphrase")
	}

	priv.Fingerprint = rek.Fingerprint

	return &priv, nil
}

func encryptPrivateKey(priv *PrivateKey, rand io.Reader, passphrase []byte, rounds int) (*rawEncryptedKey, error) {
	var rke rawEncryptedKey

	if rounds < 0 {
		rounds = defaultKDFRounds
	}
	//	if len(passphrase) == 0 {
	//		rounds = 0
	//	}

	rke.PKAlgo = algoEd
	rke.KDFAlgo = algoBcrypt
	rke.KDFRounds = uint32(rounds)
	if _, err := io.ReadFull(rand, rke.Salt[:]); err != nil {
		return nil, err
	}
	rke.Checksum = checksum(priv.Bytes[:])
	rke.Fingerprint = priv.Fingerprint

	xorkey, err := bcrypt_pbkdf.Key(passphrase, rke.Salt[:], rounds, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	for i := range rke.EncryptedKey {
		rke.EncryptedKey[i] = priv.Bytes[i] ^ xorkey[i]
	}

	return &rke, nil
}

func ParsePrivateKey(data, passphrase []byte) (*PrivateKey, error) {
	if !bytes.Equal(algoEd[:], data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}

	if !bytes.Equal(algoBcrypt[:], data[2:4]) {
		return nil, errors.New("signify: unknown kdf algorithm")
	}

	rek, err := parseRawEncryptedKey(data)
	if err != nil {
		return nil, err
	}

	return decryptPrivateKey(rek, passphrase)
}

func MarshalPrivateKey(priv *PrivateKey, rand io.Reader, passphrase []byte, rounds int) ([]byte, error) {
	rek, err := encryptPrivateKey(priv, rand, passphrase, rounds)
	if err != nil {
		return nil, err
	}

	return marshalRawEncryptedKey(rek), nil
}

func ParsePublicKey(data []byte) (*PublicKey, error) {
	if !bytes.Equal(algoEd[:], data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm")
	}

	rpk, err := parseRawPublicKey(data)
	if err != nil {
		return nil, err
	}

	pk := PublicKey{
		Bytes:       rpk.PublicKey,
		Fingerprint: rpk.Fingerprint,
	}

	return &pk, nil
}

func MarshalPublicKey(pub *PublicKey) []byte {
	return marshalRawPublicKey(&rawPublicKey{
		PKAlgo:      algoEd,
		PublicKey:   pub.Bytes,
		Fingerprint: pub.Fingerprint,
	})
}

func ParseSignature(data []byte) (*Signature, error) {
	if !bytes.Equal(algoEd[:], data[:2]) {
		return nil, errors.New("signify: unknown public key algorithm sig")
	}

	rs, err := parseRawSignature(data)
	if err != nil {
		return nil, err
	}

	sig := Signature{
		Bytes:       rs.Signature,
		Fingerprint: rs.Fingerprint,
	}
	return &sig, nil
}

func MarshalSignature(sig *Signature) []byte {
	return marshalRawSignature(&rawSignature{
		PKAlgo:      algoEd,
		Signature:   sig.Bytes,
		Fingerprint: sig.Fingerprint,
	})
}

func Sign(priv *PrivateKey, msg []byte) *Signature {
	sig := Signature{Fingerprint: priv.Fingerprint}

	s := ed25519.Sign(ed25519.PrivateKey(priv.Bytes[:]), msg)
	copy(sig.Bytes[:], s)

	return &sig
}

func Verify(pub *PublicKey, msg []byte, sig *Signature) bool {
	return ed25519.Verify(pub.Bytes[:], msg, sig.Bytes[:])
}

func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var fp [8]byte

	pubb, privb, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	_, err = io.ReadFull(rand, fp[:])
	if err != nil {
		return nil, nil, err
	}

	pub := PublicKey{Fingerprint: fp}
	priv := PrivateKey{Fingerprint: fp}

	copy(pub.Bytes[:], pubb)
	copy(priv.Bytes[:], privb)

	return &pub, &priv, nil
}

func checksum(d []byte) [8]byte {
	var chk [8]byte
	sha := sha512.New()
	sha.Write(d)
	copy(chk[:], sha.Sum(nil))
	return chk
}
