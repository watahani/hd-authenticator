
# HDAuthenticator サンプルコード

技術書典6 で配布した、WebAuthn Maniacs 第4章のサンプルコードです。

jupyterlab でも書かれているので、実際にコードを動作させて遊んでいただけます。

```sh
pip install pipenv
pipenv install
pipenv run jupyter-lab
```

## ecdsa を使ってみる
ecdsa のライブラリは `pip install ecdsa` でインストールする。


```python
import ecdsa

prikey_str = bytes.fromhex(
 '1bab84e687e36514eeaf5a017c30d32c1f59dd4ea6629da7970ca374513dd006'
)
prikey = ecdsa.SigningKey.from_string(prikey_str, curve=ecdsa.SECP256k1)

print('prikey: ',prikey_str.hex())
# prikey:  1bab84e687e36514eeaf5a017c30d32c1f59dd4ea6629da7970ca374513dd006

data = b'hello'
sign = prikey.sign(data)
print('sign  : ', sign.hex()) 
# sign  :  82f15f67976b1b397eac6b13235220c4b6a32f75db03bd5....

pubkey = prikey.get_verifying_key()

print("pub   : ",  pubkey.to_string().hex())
# pub   :  18684cfb6aefc8a7e4c08b4bad03fcd167c6e7401fe8099....

print("verified: ", pubkey.verify(sign, data))
# verified:  True
```

    prikey:  1bab84e687e36514eeaf5a017c30d32c1f59dd4ea6629da7970ca374513dd006
    sign  :  3e142e7cbeffb4502e022cb2e885086752cfc1beed066e03c7e00aee6a99e3b98a7a7913eaf6968fac16454f030ea6b40516b1f267bd7a5a77d850b242001624
    pub   :  18684cfb6aefc8a7e4c08b4bad03fcd167c6e7401fe80997e8298f9f174cfe321bf0e1edbae7b3f1f1942eefcaf0a3bedb85829c2ece5da9526071ca88be21fc
    verified:  True
    

## add secret key

秘密鍵を合成する関数。
単に int 同士の足し算をしているだけ。秘密鍵の長さあふれた分は捨てる。
なぜ big エンディアンである必要があるかは不明。


```python
from math import log2

def add_secret_keys(*args, order):
    ''' add two prikey as int and return private key of ecdsa lib'''
    prikey = 0

    for key in args:
        if prikey == 0:
            prikey = int.from_bytes(key, "big")
        else:
            prikey = (prikey + int.from_bytes(key, "big")) % order

    return prikey.to_bytes( int(log2(order)/8), 'big')

```

### 試しに足してみる



```python
k1 = '1bab84e687e36514eeaf5a017c30d32c1f59dd4ea6629da7970ca374513dd006'
k2 = '375709cd0fc6ca29dd5eb402f861a6583eb3ba9d4cc53b4f2e1946e8a27ba00c'
key1 = bytes.fromhex(k1)
expect = bytes.fromhex(k2)

result = add_secret_keys(key1, key1, order=ecdsa.SECP256k1.order )
print(result.hex())
print(result == expect)

```

    375709cd0fc6ca29dd5eb402f861a6583eb3ba9d4cc53b4f2e1946e8a27ba00c
    True
    

## 公開鍵の加算
公開鍵（楕円曲線上の点）の加算を計算します。


```python
k1 = bytes.fromhex(
  '1bab84e687e36514eeaf5a017c30d32c1f59dd4ea6629da7970ca374513dd006'
)


k1p = ecdsa.SigningKey.from_string(k1, curve=ecdsa.SECP256k1).get_verifying_key()

p = k1p.pubkey.point

p2 = p + p

k2p = ecdsa.VerifyingKey.from_public_point(p2, curve=ecdsa.SECP256k1)

print(k2p.to_string().hex())
# e0cf532282ef286226bec....
# k2 = k1*2

k2 = bytes.fromhex(
  '375709cd0fc6ca29dd5eb402f861a6583eb3ba9d4cc53b4f2e1946e8a27ba00c'
)

k2p_from_prikey = ecdsa.SigningKey.from_string(k2, curve=ecdsa.SECP256k1)\
                                  .get_verifying_key()

print(p2 == k2p_from_prikey.pubkey.point)
# True

```

    e0cf532282ef286226bece17f2e055d9bd54561883eaff73e14746765df64b3d16ed44e41c5c057ca009ccfac39f2b22ceed7c1e9d2404915576fffc27cf5cb9
    True
    

## master private key の生成

master private key は seed と key から Hmac-sha512 ハッシュを取得して 256 bit を master private key, のこりを master chain code として保存する。



```python
import hmac
import hashlib
import ecdsa
from ecdsa import SECP256k1


def hmac512(key, source):
    if isinstance(source, str):
        source = source.encode()
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, source, hashlib.sha512).digest()

def prikey_and_ccode(key, seed):
    ''' generate ECDSA private key of ecdsa lib and chain code as string'''
    hmac = hmac512(key, seed)
    prikey = hmac[:32]
    prikey = ecdsa.SigningKey.from_string(prikey, curve=ecdsa.SECP256k1)
    ccode = hmac[32:]
    return prikey, ccode

m_key, m_ccode = prikey_and_ccode('webauthn', 'techbookfest')
m_pubkey = m_key.get_verifying_key()

print("m_prikey: ", m_key.to_string().hex())
print("m_pubkey: ", m_pubkey.to_string().hex())
print("m_ccode : ", m_ccode.hex())

```

    m_prikey:  b681f32891f35b55034fc26d0317bffaf7b0ecc0f4058ca221e4bfc991cb4470
    m_pubkey:  4a467119fc2a0638eb762677fca69f6c92e8bd36dff87f30c553e4764c5fe10b7365c5190d5176d23c3956c8d0d5c2bb05406a0acdde77ab57d03851fe2b6646
    m_ccode :  39c759f2df91af229f2237ea6ed9eb102da188e68bcdab3b2913b215bfeae030
    

## 子秘密鍵の作成

子秘密鍵は、親公開鍵、インデックス、チェーンコードを利用して HMAC を計算し、その上位 256bit を親秘密鍵に加算して計算する。
最初の子鍵は m/0 と表す。


```python
def deltakey_and_ccode(index, pubkey, ccode):
    source = pubkey + index
    deltakey, child_ccode = prikey_and_ccode(key=ccode, seed=source)
    return deltakey, child_ccode

def child_key_and_ccode(index, prikey, ccode):
    ''' generate childkey from prikey and chain code'''
    pubkey = prikey.get_verifying_key().to_string()
    deltakey, child_ccode = deltakey_and_ccode(index, pubkey, ccode)
    print("deltakey  : ", deltakey.to_string().hex())
    
    child_key = add_secret_keys(
                    prikey.to_string(),
                    deltakey.to_string(),
                    order=SECP256k1.order
                )
    child_key = ecdsa.SigningKey.from_string(child_key, curve=SECP256k1)
    return child_key, child_ccode

index = 0
index = index.to_bytes(4,'big')

deltakey, _ = deltakey_and_ccode(index, m_pubkey.to_string(), m_ccode)

m_0_key, m_0_ccode = child_key_and_ccode(index, m_key, m_ccode)

print("deltakey  : ", deltakey.to_string().hex())
print("m/0 prikey: ", m_0_key.to_string().hex())
print("m/0 pubkey: ", m_0_key.get_verifying_key().to_string().hex())
print("m/0 ccode : ", m_0_ccode.hex())

```

    deltakey  :  7a822fd6977e9011e3b4b116b2143ab64c92605c1c373dcd33bf643074bba2af
    deltakey  :  7a822fd6977e9011e3b4b116b2143ab64c92605c1c373dcd33bf643074bba2af
    m/0 prikey:  310422ff2971eb66e7047383b52bfab28994703660f42a3395d1c56d3650a5de
    m/0 pubkey:  adef0692801bed2606510b9eb1680d7b02882c88def3760851bc8e3ec152bd0ac6d187b85b082e215fa4b7c4f3b86ddc7382b35728bd6a6f0424d03f99ed2206
    m/0 ccode :  96524759775e8d3bb80858ef8e975311aa0a10e8f55d4596bf2e8c21cb37d047
    

## 子鍵の子鍵を作成

以降は同様に子鍵の子鍵の子鍵…と無限にキーペアを作成可能です。


```python
index = 1
index = index.to_bytes(4, 'big')
m_0_1_key, m_0_1_ccode = child_key_and_ccode(index, m_0_key, m_0_ccode)

print("m/0/1 prikey: ", m_0_1_key.to_string().hex())
print("m/0/1 pubkey: ", m_0_1_key.get_verifying_key().to_string().hex())
print("m/0/1 ccode : ", m_0_1_ccode.hex())

```

    deltakey  :  1aecd2129285d454e5892d456707dcc9dd43fe35c3ab36ae301f4526feb413c6
    m/0/1 prikey:  4bf0f511bbf7bfbbcc8da0c91c33d77c66d86e6c249f60e1c5f10a943504b9a4
    m/0/1 pubkey:  9d63574b6578babeb3c7b21bccbbc6ff3cd0de3391b662f14bebdb94706c03bcee1061395a9e1ec0f90734fb6129c8238da352380089052ccb54c723ca60ef47
    m/0/1 ccode :  6f14f270f19c7ac300f7fc5bbb6274ed974f36b4b5ecac60244a33d71a821043
    

## 拡張公開鍵

公開鍵とチェーンコードから、子鍵の公開鍵を作成する


```python
index = 1
index = index.to_bytes(4, 'big')

m_0_pubkey = m_0_key.get_verifying_key()

m_0_1_deltakey, m_0_1_ccode = deltakey_and_ccode(index, m_0_pubkey.to_string(), m_0_ccode)
m_0_1_delta_pubkey = m_0_1_deltakey.get_verifying_key()
print("delta_pubkey:", m_0_1_delta_pubkey.to_string().hex())

m_0_1_deltakey_point = m_0_1_delta_pubkey.pubkey.point
m_0_1_point = m_0_pubkey.pubkey.point + m_0_1_deltakey_point

m_0_1_pubkey = ecdsa.VerifyingKey.from_public_point(m_0_1_point, curve=SECP256k1)

print("m/0/1_pubkey:",m_0_1_pubkey.to_string().hex())

```

    delta_pubkey: f2f2584425210aae1deca1803d019b941115a46d16c7d1cdf4279617da6e2f1b764d72e20e6471faeeb44c6b36161ac4c28a0e7a2973cd01f44b48d61a48ea6f
    m/0/1_pubkey: 9d63574b6578babeb3c7b21bccbbc6ff3cd0de3391b662f14bebdb94706c03bcee1061395a9e1ec0f90734fb6129c8238da352380089052ccb54c723ca60ef47
    

## バックアップ用 Authenticator のサンプル



```python
from ecdsa import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey
import secrets

CURVE_ORDER = SECP256k1.order
KEY_ID_LENGTH = 32
HALF_KEY_ID_LENGTH = int(KEY_ID_LENGTH/2)
CRED_ID_LENGTH = KEY_ID_LENGTH * 2

class HDKey(object):
    ''' extended key '''
    def __init__(self,keyid, prikey, ccode, pubkey, is_prikey, parentId=None, depth=0):
        self.depth = depth
        self.is_prikey = is_prikey
        self.keyid = keyid
        self.credid = (parentId + keyid) if parentId else keyid
        ccode_int = int.from_bytes(ccode, 'big')

        if not ccode or ccode_int > CURVE_ORDER:
            raise Exception('ccode must less than {}'.format(CURVE_ORDER))

        self.ccode = ccode[:]

        if is_prikey:
            if not isinstance(prikey, SigningKey):
                raise Exception('need prikey')
            self.prikey = prikey
            self.pubkey = prikey.get_verifying_key()
        else:
            self.pubkey = VerifyingKey.from_string(pubkey.to_string(), curve=pubkey.curve)
    
    def _child_key(self, keyid, include_prikey=False):
        '''generate child key'''
        if include_prikey:
            if not self.is_prikey:
                raise Exception('this key doesn\'t include prikey')
            return self._child_key_from_prikey(keyid)
        else:
            pubkey = self.pubkey
            ccode = self.ccode
            deltakey, child_ccode = deltakey_and_ccode(keyid, pubkey.to_string(), ccode)
            deltakey_point = deltakey.get_verifying_key().pubkey.point
            point = pubkey.pubkey.point + deltakey_point
            child_key = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)
            return HDKey(keyid=keyid, prikey=None,ccode=child_ccode, is_prikey=False, pubkey=child_key, parentId=self.keyid, depth=self.depth+1)

    def _child_key_from_prikey(self, keyid):
        ''' generate childkey from prikey and chain code'''
        prikey = self.prikey
        ccode = self.ccode
        pubkey = prikey.get_verifying_key().to_string()

        delta_key, child_ccode = deltakey_and_ccode(keyid, pubkey, ccode)

        child_key_str = add_secret_keys(prikey.to_string(), delta_key.to_string(), order=SECP256k1.order)
        child_key = ecdsa.SigningKey.from_string(child_key_str, curve=SECP256k1)
        return HDKey(keyid=keyid, prikey=child_key, ccode=child_ccode, pubkey=None, parentId=self.keyid, is_prikey=True, depth=self.depth+1)

    def _checksum(self, source, appid_hash=None):
        if appid_hash:
            s = source + appid_hash
        else:
            s = source
        return hmac512(self.ccode, s)[:HALF_KEY_ID_LENGTH]

    def _generateRandomKeyId(self, appid_hash=None):
        keyid_L = secrets.token_bytes(HALF_KEY_ID_LENGTH)
        
        return keyid_L + self._checksum(keyid_L,appid_hash)

    def _child_key_from_id(self, keyid, appid_hash=None):
        if self.is_child_key_id(keyid, appid_hash):
            return self._child_key(keyid,include_prikey=self.is_prikey)
        else:
            raise Exception('invalid keyid {}'.format(keyid.hex()))

    def sign(self, source):
        return self.prikey.sign(source)
    
    def verify(self, sign, source):
        return self.pubkey.verify(sign, source)

    def app_prikey(self, credid, appid_hash):
        if not self.is_prikey:
            raise Exception('this key doesn\'t prikey') 

        if len(credid) == CRED_ID_LENGTH:
            childkey = self._child_key_from_id(credid[:KEY_ID_LENGTH])
            prikey = childkey._child_key_from_id(credid[KEY_ID_LENGTH:], appid_hash)
            return prikey
        else:
            return None

    def pubkey_seed(self):
        child_keyid = self._generateRandomKeyId()
        return self._child_key(child_keyid,include_prikey=False)

    def app_pubkey(self, appid_hash):
        if not self.depth == 1:
            raise Exception('app pubkey should be generated by child key')
        elif not appid_hash:
            raise Exception('required appid_hash to generate app pubkey')
        else:
            child_keyid = self._generateRandomKeyId(appid_hash=appid_hash)
            return self._child_key(child_keyid,include_prikey=False)

    def is_child_key_id(self, keyid, appid_hash=None):
        keyid_L = keyid[:HALF_KEY_ID_LENGTH]
        keyid_R = keyid[HALF_KEY_ID_LENGTH:]

        return keyid_R == self._checksum(keyid_L, appid_hash=appid_hash)

    def print_debug(self):
        print(str(self))

    def __str__(self):
        s = '''is_prikey: {}
depth    : {}
keyid    : {}
prikey   : {}
pubkey   : {}
credid   : {}
ccode    : {}
'''
        return s.format(self.is_prikey, self.depth, self.keyid.hex(), self.prikey.to_string().hex() if self.is_prikey else None, self.pubkey.to_string().hex(), self.credid.hex(), self.ccode.hex())

m_key, m_ccode = prikey_and_ccode('webauthn', 'seed')
master_key_index = 0
master_key = HDKey(keyid=master_key_index.to_bytes(0, 'big'), prikey=m_key, ccode=m_ccode, pubkey=None, is_prikey=True)

print("======== master_key ==========")

master_key.print_debug()

print("======== pubkey_seed ==========")

pubkey_seed = master_key.pubkey_seed()

pubkey_seed.print_debug()

print("======== app_pubkey ==========")

appid = 'https://example.com'

appid_hash = hashlib.sha256(appid.encode()).digest()

app_pubkey=pubkey_seed.app_pubkey(appid_hash)

app_pubkey.print_debug()

print("======== private key ==========")

prikey = master_key.app_prikey(app_pubkey.credid, appid_hash)

prikey.print_debug()

source = 'nonce'.encode()
sign = prikey.sign(source)
result = app_pubkey.verify(sign, source)

print("========   result   ==========")

print('souce :','nonce')
print('pubkey:', app_pubkey.pubkey.to_string().hex())
print('sign  :', sign.hex())
print('result:', result)

```

    ======== master_key ==========
    is_prikey: True
    depth    : 0
    keyid    : 
    prikey   : c0efe2a00cfe3d31fe84b0d72366842392fe374730d02dcc50e690284fafa863
    pubkey   : 323cea14302640267a9db642c9fab532167e5ef64d2b878dd4cb8b09251feb1755eca3378af50bab6e5fd156de6529d31d7e7f955e341616f783afe9fc3302b0
    credid   : 
    ccode    : f96fe3c225726a7ee001dcd98349593a76f797ec5cde9abff844cb55ebf9f506
    
    ======== pubkey_seed ==========
    is_prikey: False
    depth    : 1
    keyid    : f1505fced5a0a68a99dbd17a5b2aa987a640e9f5a5b15e64721aecee873dc4e1
    prikey   : None
    pubkey   : 552d3ee8b62c9384a1f1d9a14ff87e3167886e0da416c6d2cb9e57b197a116d8594392d93b6e8f3987f8ea579ee01fc29cdd598ddc406d30196633008a1e944d
    credid   : f1505fced5a0a68a99dbd17a5b2aa987a640e9f5a5b15e64721aecee873dc4e1
    ccode    : 54922b19b44419852e96acc30c0e811fc2f5ea5733cca7f62fee52f09db80b85
    
    ======== pubkey ==========
    is_prikey: False
    depth    : 2
    keyid    : b248c55f3c90226d4b2cf2e374760aec800f6b98256da2910064c292ff6820d2
    prikey   : None
    pubkey   : d6b5ae0305843a420faa1ef17c13af1318af543d7b7a2747abd4055c87615c2528a4b89e7d764bada8d17485bc09014a61e2b36680875477440ebe095e50631b
    credid   : f1505fced5a0a68a99dbd17a5b2aa987a640e9f5a5b15e64721aecee873dc4e1b248c55f3c90226d4b2cf2e374760aec800f6b98256da2910064c292ff6820d2
    ccode    : 4b9a7a103066f61157a587573e41121e7af1a7c2e47e76a712375570b7d76470
    
    True


