package screed

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/securepollingsystem/tallyspider/securepollingsystem"
)

type Screed struct {
	screedText      string
	screedSig       btcec.Signature
	voterPubKey     btcec.PublicKey
	registrarSig    btcec.Signature
	registrarPubKey btcec.PublicKey
}

func NewScreed(screedText string, screedSig btcec.Signature, pubKey btcec.PublicKey, pubKeySig btcec.Signature, regPubKey btcec.PublicKey) *Screed {
	return &Screed{screedText, screedSig, pubKey, pubKeySig, regPubKey}
}

func TrimScreedHeaderFooter(screedText string) string {
	tmpString := strings.TrimPrefix(screedText, securepollingsystem.ScreedPrefix+"\n")
	return strings.TrimSuffix(tmpString, "\n"+securepollingsystem.ScreedSuffix)
}

func TrimScreedSigHeaderFooter(screedSigText string) string {
	tmpString := strings.TrimPrefix(screedSigText, securepollingsystem.ScreedSigPrefix+"\n")
	return strings.TrimSuffix(tmpString, "\n"+securepollingsystem.ScreedSigSuffix)
}

func DeserializeScreed(screedString string) (*Screed, error) {
	screedRegExp, err := regexp.Compile(securepollingsystem.ScreedPrefix + `[\s\S]+?` + securepollingsystem.ScreedSuffix)
	if err != nil {
		return nil, fmt.Errorf("Error regex-parsing screed: %v", err)
	}

	screedSigRegExp, err := regexp.Compile(securepollingsystem.ScreedSigPrefix + `[\s\S]+?` + securepollingsystem.ScreedSigSuffix)
	if err != nil {
		return nil, fmt.Errorf("Error regex-parsing screed suffix: %v", err)
	}

	screedText := TrimScreedHeaderFooter(screedRegExp.FindString(screedString))
	screedSigText := TrimScreedSigHeaderFooter(screedSigRegExp.FindString(screedString))

	screedBytes, err := base64.StdEncoding.DecodeString(screedSigText)
	if err != nil {
		return nil, fmt.Errorf("Error decoding screed sig: %v", err)
	}

	screedBuf := &securepollingsystem.Screed{}
	err = proto.Unmarshal(screedBytes, screedBuf)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling screed to protobuf: %v", err)
	}

	screedSig, err := btcec.ParseSignature([]byte(*screedBuf.ScreedSig), btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Error parsing signature: %v", err)
	}

	voterPubKey, err := btcec.ParsePubKey([]byte(*screedBuf.VoterPubKey), btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Error parsing pub key: %v", err)
	}
	screedHash := sha256.Sum256([]byte(screedText))
	if !screedSig.Verify(screedHash[:], voterPubKey) {
		return nil, errors.New("Invalid screed signature")
	}

	registrarSig, err := btcec.ParseSignature([]byte(*screedBuf.RegistrarSig), btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Error parsing signature: %v", err)
	}

	//TO DO check if we accept this registrars public key
	registrarPubKey, err := btcec.ParsePubKey([]byte(*screedBuf.RegistrarPubKey), btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Error parsing public key: %v", err)
	}

	pubKeyHash := sha256.Sum256(voterPubKey.SerializeCompressed())
	if !registrarSig.Verify(pubKeyHash[:], registrarPubKey) {
		return nil, errors.New("Invalid Signature of Voter Pub Key")
	}

	return &Screed{screedText, *screedSig, *voterPubKey, *registrarSig, *registrarPubKey}, nil
}

func (screed *Screed) Serialize() (string, error) {

	screedBuf := &securepollingsystem.Screed{
		ScreedSig:       proto.String(string(screed.screedSig.Serialize())),
		VoterPubKey:     proto.String(string(screed.voterPubKey.SerializeCompressed())),
		RegistrarSig:    proto.String(string(screed.registrarSig.Serialize())),
		RegistrarPubKey: proto.String(string(screed.registrarPubKey.SerializeCompressed())),
	}
	payloadBytes, err := proto.Marshal(screedBuf)
	if err != nil {
		return "", err
	}

	payload := securepollingsystem.EncodeToString(payloadBytes)

	// payload := securepollingsystem.EncodeToString(screed.screedSig.Serialize(), screed.voterPubKey.SerializeCompressed(), screed.registrarSig.Serialize(), regPubKey.SerializeCompressed())

	screedStr := securepollingsystem.ScreedPrefix + "\n" + screed.screedText + "\n" + securepollingsystem.ScreedSuffix + "\n" + securepollingsystem.ScreedSigPrefix + "\n" + payload + "\n" + securepollingsystem.ScreedSigSuffix

	return screedStr, nil
}
