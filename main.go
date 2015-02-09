package main

import (
    // "fmt"
    "io/ioutil"
    "crypto/sha256"
    "regexp"
    "strings"
    "github.com/btcsuite/btcd/btcec"
    b64 "encoding/base64"
    // "github.com/PuerktoBio/fetchbot"
)


func check(e error) {
    if e != nil {
        panic(e)
    }
}

var screedPrefix = `-----BEGIN SPS SCREED TXT-----`
var screedSuffix= `-----END SPS TXT SCREED-----`
var screedSigPrefix = `-----BEGIN SPS SCREED SIG-----`
var screedSigSuffix = `-----END SPS SCREED SIG-----`



func TrimHeaderFooter(screedText string) string {
  
  tmpString := strings.TrimPrefix(screedText, screedPrefix+"\n")
  return strings.TrimSuffix(tmpString,"\n"+screedSuffix)
  
  }

func EncodeToString(chunks ...[]byte) string{
  var stringSum string
  
  for _, chunk := range chunks {
    stringSum = stringSum + b64.StdEncoding.EncodeToString(chunk)
    }
  
  return stringSum
  }



func main() {
  
  
  
  screedReg, err := regexp.Compile(screedPrefix +`[\s\S]+?` + screedSuffix)
  check(err)
  
  screedBegin :="-----BEGIN SPS SCREED TXT-----\nI really like ice cream\n-----END SPS TXT SCREED-----"
  
  screedText := screedReg.FindString(screedBegin)

  screedHash := sha256.Sum256([]byte(screedText))
  
  
  regPkBytes := sha256.Sum256([]byte("This is Registrar key seed"))
  
  pkBytes := sha256.Sum256([]byte("My key seed"))
  
  privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes[:])
  
  regPrivKey, regPubKey := btcec.PrivKeyFromBytes(btcec.S256(), regPkBytes[:])
  
  pubKeySig, err := regPrivKey.Sign(pubKey.SerializeCompressed())
  check(err)
  
  screedSig, err := privKey.Sign(screedHash[:])
  check(err)

  payload := EncodeToString(screedSig.Serialize(), pubKey.SerializeCompressed(), pubKeySig.Serialize(), regPubKey.SerializeCompressed())
  
  dataForFile := screedBegin + "\n" + screedSigPrefix +"\n" + payload + "\n" + screedSigSuffix

  err = ioutil.WriteFile("example_screed.txt", []byte(dataForFile), 0644)
  check(err)



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

