// Code generated by protoc-gen-go.
// source: protos/screed.proto
// DO NOT EDIT!

/*
Package securepollingsystem is a generated protocol buffer package.

It is generated from these files:
	protos/screed.proto

It has these top-level messages:
	Screed
*/
package securepollingsystem

import (
	"encoding/base64"
	"errors"
	"math"

	"github.com/golang/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = math.Inf

var (
	ScreedPrefix        = `-----BEGIN SPS SCREED TXT-----`
	ScreedSuffix        = `-----END SPS TXT SCREED-----`
	ScreedSigPrefix     = `-----BEGIN SPS SCREED SIG-----`
	ScreedSigSuffix     = `-----END SPS SCREED SIG-----`
	SerializedSigLength = 71
	SerializedKeyLength = 33
)

type Screed struct {
	ScreedSig        *string `protobuf:"bytes,1,req,name=screedSig" json:"screedSig,omitempty"`
	VoterPubKey      *string `protobuf:"bytes,2,req,name=voterPubKey" json:"voterPubKey,omitempty"`
	RegistrarSig     *string `protobuf:"bytes,3,req,name=registrarSig" json:"registrarSig,omitempty"`
	RegistrarPubKey  *string `protobuf:"bytes,4,req,name=registrarPubKey" json:"registrarPubKey,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Screed) Reset()         { *m = Screed{} }
func (m *Screed) String() string { return proto.CompactTextString(m) }
func (*Screed) ProtoMessage()    {}

func (m *Screed) GetScreedSig() string {
	if m != nil && m.ScreedSig != nil {
		return *m.ScreedSig
	}
	return ""
}

func (m *Screed) GetVoterPubKey() string {
	if m != nil && m.VoterPubKey != nil {
		return *m.VoterPubKey
	}
	return ""
}

func (m *Screed) GetRegistrarSig() string {
	if m != nil && m.RegistrarSig != nil {
		return *m.RegistrarSig
	}
	return ""
}

func (m *Screed) GetRegistrarPubKey() string {
	if m != nil && m.RegistrarPubKey != nil {
		return *m.RegistrarPubKey
	}
	return ""
}

func init() {
}

func (m *Screed) Valid() error {
	if m == nil {
		return errors.New("*Screed is nil")
	}

	if m.ScreedSig == nil {
		return errors.New("screed.ScreedSig is nil")
	}
	if m.VoterPubKey == nil {
		return errors.New("screed.VoterPubKey is nil")
	}
	if m.RegistrarSig == nil {
		return errors.New("screed.RegistrarSig is nil")
	}
	if m.RegistrarPubKey == nil {
		return errors.New("screed.RegistrarPubKey is nil")
	}

	return nil
}

func EncodeToString(chunks ...[]byte) string {
	var stringSum string

	for _, chunk := range chunks {
		stringSum = stringSum + base64.StdEncoding.EncodeToString(chunk)
	}

	return stringSum
}
