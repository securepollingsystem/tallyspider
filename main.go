package main

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"io/ioutil"
	"regexp"
	"strings"
	// "github.com/PuerktoBio/fetchbot"
	"github.com/golang/protobuf/proto"
	"github.com/securepollingsystem/tallyspider/protos"
)

func check(e error, function string) {
	if e != nil {
                fmt.Println("Panic during "+function)
		panic(e)
	}
}

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
		stringSum = stringSum + b64.StdEncoding.EncodeToString(chunk)
	}

	return stringSum
}

func DeserializeScreed(screedString string) (*Screed, error, string) {
	screedRegExp, err := regexp.Compile(screedPrefix + `[\s\S]+?` + screedSuffix)
	if err != nil {
		return nil, err, "regexp.Compile(screedPrefix + `[\\s\\S]+?` + screedSuffix)"
	}

	screedSigRegExp, err := regexp.Compile(screedSigPrefix + `[\s\S]+?` + screedSigSuffix)
	if err != nil {
		return nil, err, "regexp.Compile(screedSigPrefix + `[\\s\\S]+?` + screedSigSuffix)"
	}

	screedText := TrimScreedHeaderFooter(screedRegExp.FindString(screedString))
	screedSigText := TrimScreedSigHeaderFooter(screedSigRegExp.FindString(screedString))

	screedBytes, err := b64.StdEncoding.DecodeString(screedSigText)
	if err != nil {
		return nil, err, "b64.StdEncoding.DecodeString(screedSigText)"
	}

	screedBuf := &securepollingsystem.Screed{}
	err = proto.Unmarshal(screedBytes, screedBuf)
	if err != nil {
		return nil, err, "proto.Unmarshal(screedBytes, screedBuf)"
	}

	screedSig, err := btcec.ParseSignature([]byte(*screedBuf.ScreedSig), btcec.S256())
	if err != nil {
		return nil, err, "btcec.ParseSignature([]byte(*screedBuf.ScreedSig), btcec.S256())"
	}

	voterPubKey, err := btcec.ParsePubKey([]byte(*screedBuf.VoterPubKey), btcec.S256())
	if err != nil {
		return nil, err, "btcec.ParsePubKey([]byte(*screedBuf.VoterPubKey), btcec.S256())"
	}
	screedHash := sha256.Sum256([]byte(screedText))
	if !screedSig.Verify(screedHash[:], voterPubKey) {
		return nil, nil, "Invalid Signature of Screed"
	}

	registrarSig, err := btcec.ParseSignature([]byte(*screedBuf.RegistrarSig), btcec.S256())
	if err != nil {
		return nil, err, "btcec.ParseSignature([]byte(*screedBuf.RegistrarSig), btcec.S256())"
	}

	//TO DO check if we accept this registrars public key
	registrarPubKey, err := btcec.ParsePubKey([]byte(*screedBuf.RegistrarPubKey), btcec.S256())
	if err != nil {
		return nil, err, "btcec.ParsePubKey([]byte(*screedBuf.RegistrarPubKey), btcec.S256())"
	}

	pubKeyHash := sha256.Sum256(voterPubKey.SerializeCompressed())
	if !registrarSig.Verify(pubKeyHash[:], registrarPubKey) {
		return nil, nil, "Invalid Signature of Voter Pub Key"
	}

	return &Screed{screedText, *screedSig, *voterPubKey, *registrarSig, *registrarPubKey}, nil, ""
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
	check(err,"regPrivKey.Sign(pubKeyHash[:])")

	screedSig, err := privKey.Sign(screedHash[:])
	check(err,"privKey.Sign(screedHash[:])")
	fmt.Println(len(screedSig.Serialize()))
	fmt.Println(len(pubKey.SerializeCompressed()))
	fmt.Println(len(pubKeySig.Serialize()))
	fmt.Println(len(regPubKey.SerializeCompressed()))

	screedObj := Screed{screedText, *screedSig, *pubKey, *pubKeySig, *regPubKey}
	dataForFile := screedObj.Serialize()

	screedObj2, err, errstring := DeserializeScreed(dataForFile)
	check(err,errstring)
	screedObj3, err, errstring := DeserializeScreed(screedObj2.Serialize())
	check(err,errstring)

	fmt.Println(screedObj)
	fmt.Println(screedObj2)
	fmt.Println(screedObj3)

	err = ioutil.WriteFile("example_screed.txt", []byte(dataForFile), 0644)
	check(err,"ioutil.WriteFile(\"example_screed.txt\", []byte(dataForFile), 0644)")

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
