package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	// "github.com/PuerktoBio/fetchbot"
	securepollingsystem "github.com/securepollingsystem/tallyspider/protos"
)

var screedPrefix = `-----BEGIN SPS SCREED TXT-----`
var screedSuffix = `-----END SPS TXT SCREED-----`
var screedSigPrefix = `-----BEGIN SPS SCREED SIG-----`
var screedSigSuffix = `-----END SPS SCREED SIG-----`
var serializedSigLength = 71
var serializedKeyLength = 33

type Screed struct {
	screedText      string
	screedSig       btcec.Signature
	voterPubKey     btcec.PublicKey
	registrarSig    btcec.Signature
	registrarPubKey btcec.PublicKey
}

func TrimScreedHeaderFooter(screedText string) string {
	tmpString := strings.TrimPrefix(screedText, screedPrefix+"\n")
	return strings.TrimSuffix(tmpString, "\n"+screedSuffix)
}

func TrimScreedSigHeaderFooter(screedSigText string) string {
	tmpString := strings.TrimPrefix(screedSigText, screedSigPrefix+"\n")
	return strings.TrimSuffix(tmpString, "\n"+screedSigSuffix)
}

func EncodeToString(chunks ...[]byte) string {
	var stringSum string

	for _, chunk := range chunks {
		stringSum = stringSum + base64.StdEncoding.EncodeToString(chunk)
	}

	return stringSum
}

func DeserializeScreed(screedString string) (*Screed, error) {
	screedRegExp, err := regexp.Compile(screedPrefix + `[\s\S]+?` + screedSuffix)
	if err != nil {
		return nil, fmt.Errorf("Error regex-parsing screed: %v", err)
	}

	screedSigRegExp, err := regexp.Compile(screedSigPrefix + `[\s\S]+?` + screedSigSuffix)
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

func (screed *Screed) Serialize() string {

	screedBuf := &securepollingsystem.Screed{
		ScreedSig:       proto.String(string(screed.screedSig.Serialize())),
		VoterPubKey:     proto.String(string(screed.voterPubKey.SerializeCompressed())),
		RegistrarSig:    proto.String(string(screed.registrarSig.Serialize())),
		RegistrarPubKey: proto.String(string(screed.registrarPubKey.SerializeCompressed())),
	}
	payloadBytes, _ := proto.Marshal(screedBuf)

	payload := EncodeToString(payloadBytes)

	// payload := EncodeToString(screed.screedSig.Serialize(), screed.voterPubKey.SerializeCompressed(), screed.registrarSig.Serialize(), regPubKey.SerializeCompressed())

	return screedPrefix + "\n" + screed.screedText + "\n" + screedSuffix + "\n" + screedSigPrefix + "\n" + payload + "\n" + screedSigSuffix
}

func main() {
	screedText := "I really like ice cream\n"

	screedHash := sha256.Sum256([]byte(screedText))

	regPkBytes := sha256.Sum256([]byte("This is Registrar key seed"))

	pkBytes := sha256.Sum256([]byte("My key seed"))

	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes[:])

	regPrivKey, regPubKey := btcec.PrivKeyFromBytes(btcec.S256(), regPkBytes[:])

	pubKeyHash := sha256.Sum256(pubKey.SerializeCompressed())

	pubKeySig, err := regPrivKey.Sign(pubKeyHash[:])
	if err != nil {
		panic("Error from regPrivKey.Sign(pubKeyHash[:]) -- " + err.Error())
	}

	screedSig, err := privKey.Sign(screedHash[:])
	if err != nil {
		panic("Error from privKey.Sign(screedHash[:]) -- " + err.Error())
	}

	fmt.Println(len(screedSig.Serialize()))
	fmt.Println(len(pubKey.SerializeCompressed()))
	fmt.Println(len(pubKeySig.Serialize()))
	fmt.Println(len(regPubKey.SerializeCompressed()))

	screedObj := Screed{screedText, *screedSig, *pubKey, *pubKeySig, *regPubKey}
	dataForFile := screedObj.Serialize()

	screedObj2, err := DeserializeScreed(dataForFile)
	if err != nil {
		panic("Error from DeserializeScreed: " + err.Error())
	}

	screedObj3, err := DeserializeScreed(screedObj2.Serialize())
	if err != nil {
		panic("Error from DeserializeScreed.Serialize: " + err.Error())
	}

	fmt.Println(screedObj)
	fmt.Println(screedObj2)
	fmt.Println(screedObj3)

	err = ioutil.WriteFile("example_screed.txt", []byte(dataForFile), 0644)
	if err != nil {
		panic("Error writing example file: " + err.Error())
	}

	// screed, err := ioutil.ReadFile("example_screed.txt")
	// check(err)

	// signature, err := ioutil.ReadFile("example_screed.txt.sig")
	// check(err)

	// pubverifySignature(signature, screed)
	// fmt.Printf("PubKey: %v")

	// f := fetchbot.New(fetchbot.HandlerFunc(handler))
	// queue := f.Start()
	// queue.SendStringHead("http://google.com", "http://golang.org", "http://golang.org/doc")
	// queue.Close()
}

// func handler(ctx *fetchbot.Context, res *http.Response, err error) {
//     if err != nil {
//         fmt.Printf("error: %s\n", err)
//         return
//     }
//     fmt.Printf("[%d] %s %s\n", res.StatusCode, ctx.Cmd.Method(), ctx.Cmd.URL())
// }
