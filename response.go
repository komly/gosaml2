package saml2

import (
	"bytes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
)

//Response is an abstraction type for handling the information in a SAML
//assertion
type Response struct {
	Destination      string           `xml:"Destination,attr"`
	Issuer           string           `xml:"Issuer"`
	Value            string           `xml:",attr"`
	EncryptionMethod EncryptionMethod `xml:"EncryptedAssertion>EncryptedData>EncryptionMethod"`
	Key              EncryptedKey     `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data             string           `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
	Signature        string           `xml:"Signature>SignatureValue"`
	Digest           string           `xml:"Signature>SignedInfo>Reference>DigestValue"`
}

//NewResponseFromReader returns a Response or error based on the given reader.
func NewResponseFromReader(r io.Reader) (*Response, error) {
	var res Response

	//Decode and copy bytes into buffer
	err := xml.NewDecoder(r).Decode(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

//Decrypt returns the byte slice contained in the encrypted data.
func (sr *Response) Decrypt(cert tls.Certificate) ([]byte, error) {
	data, err := xmlBytes(sr.Data)
	if err != nil {
		return nil, err
	}

	k, err := sr.Key.DecryptSymmetricKey(cert)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt, error retrieving private key: %s", err)
	}

	switch sr.EncryptionMethod.Algorithm {
	case MethodAES128GCM:
		c, err := cipher.NewGCM(k)
		if err != nil {
			return nil, fmt.Errorf("cannot create AES-GCM: %s", err)
		}

		nonce, data := data[:c.NonceSize()], data[c.NonceSize():]
		plainText, err := c.Open(nil, nonce, data, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot open AES-GCM: %s", err)
		}
		return plainText, nil
	case MethodAES128CBC, MethodAES256CBC:
		nonce, data := data[:k.BlockSize()], data[k.BlockSize():]
		c := cipher.NewCBCDecrypter(k, nonce)
		c.CryptBlocks(data, data)

		// Remove zero bytes
		data = bytes.TrimRight(data, "\x00")

		// Calculate index to remove based on padding
		padLength := data[len(data)-1]
		lastGoodIndex := len(data) - int(padLength)
		return data[:lastGoodIndex], nil
	default:
		return nil, fmt.Errorf("unknown symmetric encryption method %#v", sr.EncryptionMethod.Algorithm)
	}
}
