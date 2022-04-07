package privacy

import (
    "crypto/aes"
    "crypto/cipher"
    "errors"
    "sync"
    "fmt"
)

// times indicates how many times the node should be retrieved
// size indicates origin file size
type NodeInfo struct {
    times     map[string]int
    size      int64
    allBlkNum int
    sndBlkNum int
}

type Privacy struct {
    secretKey      []byte
    cids           map[string]NodeInfo
    cidsLock       sync.Mutex
}

var Prv *Privacy = nil
var MINGETTIMES int = 3

func init() {
    Prv = NewPrivacy(make([]byte, 0))
}

func NewPrivacy(key []byte) *Privacy {
    return &Privacy{
        secretKey: key,
        cids: make(map[string]NodeInfo),
    }
}

func (p *Privacy) AddCidInfo(path string, cid string, size int64) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()

    if _, ok := p.cids[path]; !ok {
        p.cids[path] = NodeInfo{
            make(map[string]int),
            0,
            0,
            0,
        }
    }

    entry, _ := p.cids[path]
    entry.times[cid] += MINGETTIMES
    entry.size += size
    entry.allBlkNum += MINGETTIMES
    p.cids[path] = entry
}

func (p *Privacy) GetProgress(cid string) (int, error) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    if entry, ok := p.cids[cid]; ok {
        return entry.sndBlkNum / entry.allBlkNum, nil
    }
    return 0, fmt.Errorf("cid(%s) not found.", cid)
}

func (p *Privacy) GetRealSize(cid string) (int64, error) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    if _, ok := p.cids[cid]; !ok {
        return 0, fmt.Errorf("cid(%s) not found.", cid)
    }
    return p.cids[cid].size, nil
}

func (p *Privacy) RemoveFileInfo(cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    delete(p.cids, cid)
}

func (p *Privacy) SetFileInfo(path string, cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    p.cids[cid] = p.cids[path]
    delete(p.cids, path)
}

func (p *Privacy) UpdateFileInfo(cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    for k, v := range p.cids {
        if _, ok := v.times[cid]; ok {
            v.times[cid]--
            if v.times[cid] > 0 {
                v.sndBlkNum++
            }
            p.cids[k] = v
            return
        }
    }
}

func (p *Privacy) TriggerEnd(cid string) bool {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    return p.cids[cid].allBlkNum == p.cids[cid].sndBlkNum
}

func (p *Privacy) SetKey(key []byte) error {
    if len(p.secretKey) != 0 {
        return errors.New("Private key has been set.")
    }
    p.secretKey = key
    return nil
}


// --------------- Crypto related --------------- //
func (p *Privacy) Encrypt(plainText []byte) ([]byte, error) {
    if len(p.secretKey) == 0 {
        return nil, errors.New("Secret key has been not set.")
    }

    c, err := aes.NewCipher(p.secretKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())

    return gcm.Seal(nonce, nonce, plainText, nil), nil
}

func (p *Privacy) Decrypt(cipherText []byte) ([]byte, error) {
    if len(p.secretKey) == 0 {
        return nil, errors.New("Secret key has been not set.")
    }

    c, err := aes.NewCipher(p.secretKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(cipherText) < nonceSize {
        return nil, errors.New("cipherText too short")
    }

    nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
    return gcm.Open(nil, nonce, cipherText, nil)
}
