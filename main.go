package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/securepollingsystem/tallyspider/screed"
	// "github.com/PuerktoBio/fetchbot"
)

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

	screedObj := screed.NewScreed(screedText, *screedSig, *pubKey, *pubKeySig, *regPubKey)
	dataForFile, err := screedObj.Serialize()
	if err != nil {
		panic("Error serializing screed: " + err.Error())
	}

	screedObj2, err := screed.DeserializeScreed(dataForFile)
	if err != nil {
		panic("Error from DeserializeScreed: " + err.Error())
	}

	screedObj2Str, err := screedObj2.Serialize()
	if err != nil {
		panic("Error serializing screedObj2: " + err.Error())
	}

	screedObj3, err := screed.DeserializeScreed(screedObj2Str)
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
