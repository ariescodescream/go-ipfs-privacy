package privacy

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
    "sync"
    "context"
    "bytes"
    "fmt"
    ipld "github.com/ipfs/go-ipld-format"
    cids "github.com/ipfs/go-cid"
)

type NodeInfo struct {
    times map[string]int
    order *Vector
}

type Privacy struct {
    secretKey      []byte
    cids           map[string]NodeInfo
    cidsLock       sync.Mutex
    compBlkNum     map[string]int
    compBlkNumLock sync.Mutex

    ctx            context.Context
    dagServ        ipld.DAGService
    rootCid        cids.Cid
}

var Prv *Privacy = nil
var MINGETTIMES int = 5

func init() {
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        fmt.Println(err)
    }
    Prv = NewPrivacy(key)
}

func NewPrivacy(key []byte) *Privacy {
    return &Privacy{
        secretKey: key,
        cids: make(map[string]NodeInfo),
    }
}

func (p *Privacy) addCidInfo(path string, cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()

    if _, ok := p.cids[path]; !ok {
        p.cids[path] = NodeInfo{
            make(map[string]int),
            NewVector(0),
        }
    }

    p.cids[path].times[cid] += MINGETTIMES
    p.cids[path].order.Append(cid)
}

func (p *Privacy) clearFileInfo() {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    p.cids = make(map[string]NodeInfo)
}

func (p *Privacy) setFileInfo(path string, cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    p.cids[cid] = p.cids[path]
    delete(p.cids, path)
}

func (p *Privacy) updateFileInfo(cid string) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    for key := range p.cids {
        if _, ok := p.cids[key].times[cid]; ok {
            p.cids[key].times[cid]--
            if p.cids[key].times[cid] == 0 {
                p.compBlkNumLock.Lock()
                defer p.compBlkNumLock.Unlock()
                p.compBlkNum[key]++
            }
            return
        }
    }
}

func (p *Privacy) setContext(ctx context.Context, dagServ ipld.DAGService, cid cids.Cid) {
    p.ctx = ctx
    p.dagServ = dagServ
    p.rootCid = cid
}

func (p *Privacy) getReader() (io.Reader, error) {
    p.cidsLock.Lock()
    defer p.cidsLock.Unlock()
    cid := p.rootCid.String()
    if _, ok := p.cids[cid]; !ok {
        return nil, errors.New("Indicated cid is not existed")
    }

    var b bytes.Buffer
    size := p.cids[cid].order.Size()
    for i := 0; i < size; i++ {
        child, _ := p.cids[cid].order.At(i)
        rcid, parseErr := cids.Parse(child)
        if parseErr != nil {
            return nil, parseErr
        }

        node, getErr := p.dagServ.Get(p.ctx, rcid)
        if getErr != nil {
            return nil, getErr
        }

        cb, decErr := p.decrypt(node.RawData())
        if decErr != nil {
            return nil, decErr
        }
        b.Write(cb)
    }
    return &b, nil
}

func (p *Privacy) triggerEnd(cid string) bool {
    p.compBlkNumLock.Lock()
    defer p.compBlkNumLock.Unlock()
    return p.compBlkNum[cid] == len(p.cids[cid].times)
}

func (p *Privacy) setKey(key []byte) {
    p.secretKey = key
}


// --------------- Encrypto related --------------- //
func (p *Privacy) encrypt(plainText []byte) ([]byte, error) {
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

func (p *Privacy) decrypt(cipherText []byte) ([]byte, error) {
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
