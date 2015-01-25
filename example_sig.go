package main

import (
    "fmt"
    // "net/http"
    "io/ioutil"
    "crypto/sha256"
    "github.com/btcsuite/btcec"
    "github.com/btcsuite/btcwire"

    // "github.com/PuerkitoBio/fetchbot"
)


func check(e error) {
    if e != nil {
        panic(e)
    }
}




func signMessage(message string , pkBytes [32]byte ) []byte {
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes[0:])

	// Sign a message using the private key.
	messageHash := btcwire.DoubleSha256([]byte(message))
	signature, err := privKey.Sign(messageHash)
  check(err)

	// Serialize and display the signature.
	//
	// NOTE: This is commented out for the example since the signature
	// produced uses random numbers and therefore will always be different.
	//fmt.Printf("Serialized Signature: %x\n", signature.Serialize())

	// Verify the signature for the message using the public key.
	verified := signature.Verify(messageHash, pubKey)
	fmt.Printf("Signature Verified? %v\n", verified)

	// Output:
	// Signature Verified? true
  return signature.Serialize()


}




func main() {
  
    seedBytes := []byte("A hella insecure key")
    pkBytes := sha256.Sum256(seedBytes)
  
    screed, err := ioutil.ReadFile("example_screed.txt")
    
    check(err)
    sigBytes := signMessage(string(screed), pkBytes)
    fmt.Printf("Signature: %x", sigBytes)
    err = ioutil.WriteFile("example_screed.txt.sig",sigBytes , 0644)
    check(err)
  
  
  
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

