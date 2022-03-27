package privacy

import (
    "io"
    "fmt"
    "testing"
    "crypto/rand"
)

func TestEncrypt(t *testing.T) {
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        t.FailNow()
    }
    p := NewPrivacy(key)
    plainText := make([]byte, 34)
    cipherText, _ := p.Encrypt(plainText)
    fmt.Printf("plain text length:%d\n", len(plainText))
    fmt.Printf("cipher text length:%d\n", len(cipherText))
}

func TestWholeEncrypt(t *testing.T) {
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        t.FailNow()
    }
    p := NewPrivacy(key)
    var str1 = "hello"
    var str2 = "world"
    cipher1, _ := p.Encrypt([]byte(str1))
    cipher2, _ := p.Encrypt([]byte(str2))
    buf := make([]byte, len(cipher1)+len(cipher2))
    copy(buf, cipher1)
    copy(buf[len(cipher1):], cipher2)
    plain, err := p.Decrypt(buf)
    if err != nil {
        fmt.Println(err)
    } else {
        fmt.Printf("plain:%s\n", plain)
    }
}
