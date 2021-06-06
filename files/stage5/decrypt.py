files = {
    '68963B6C026C3642': ('40f865fb77c3fd6a3eb9567b4ad52016095d152dc686e35c3321a06f105bcaba', bytes.fromhex('696464b99ff1e025105f6235fa67c91d')),
    '675160efed2d139b': ('63e5d570187fb2a1933d931ccd1e0b068ab0ff27a98ab7461ec30cb2d0510f5e', bytes.fromhex('99a2ded8dde36c78fc5dc65053d9f512')),
    '6fc51949a75bfa98': ('15e17a4e89e609832b5a8d389a6cb62b1242cacce44501a2cf57d4d202178716', bytes.fromhex('31b2a4202f39857169fa60e15b5a3559')),
    '583c5e51d0e1ab05': ('3615b9049cabb9618aca05de639f89298e23c3d83fe82a24a0a488262148d299', bytes.fromhex('ec55393766d70f07b8e5e44dab0accb4')),
    '08ABDA216C40B90C': ('48e3847a2774bf900c2cda70503dab44e37b5cfe14e0367b555e246bf2e75943', bytes.fromhex('e5ccff13eb6e312b33b452ecbc0af0ac')),
    '1D0DFAA715724B5A': ('5534d32f4fd6a1454d55924291fc1d179ff84521920272ae4e8ae718e0c39392', bytes.fromhex('6b636b81619f2088489246eb2cfb6e23')),
    '3A8AD6D7F95E3487': ('581ed636bd7a1bbab890aeb1b458bb4f3bff59827afdd8582486ff0a22944aec', bytes.fromhex('682e887985c63472dc0271d9e5210636')),
    '325149E3FC923A77': ('1026f340ad5175f2a73d2e3513d69ffd96285ca9ec89f50629a3426e6be45b09', bytes.fromhex('72b79ca42d9034260a463a195aef53b7')),
    '46DCC15BCD2DB798': ('f0808dfbf75a5afaddff38574fe2bf03f2ff43b78cfca74aace782e06bc69511', bytes.fromhex('5a24c3efef33c97cdb0e7dbf2bf9579b')),
    '4CE294122B6BD2D7': ('96fe4e62d09539ad93093c441766dfc0011dc824ab4b9b90f6b366cd9578ccbf', bytes.fromhex('d0bdadd7940e77f6e41c4ec8f3174589')),
    '4145107573514DCC': ('11b1aef316795c3a3a440596216dd288fbee939689fad49e82d78baf52b574da', bytes.fromhex('f9f81180deb3fb4a1132d794536b7832')),
    '6811AF029018505F': ('4e40398697616f77509274494b08a687dd5cc1a7c7a5720c75782ab9b3cf91af', bytes.fromhex('64670bf9fe8ac6c438a9c1f55465088e')),
    'D603C7E177F13C40': ('e1428828ed32e37beba57986db574aae48fde02a85c092ac0d358b39094b2328', bytes.fromhex('db6f435ef9deed881fea7e51706fe297')), # prod
    'ED6787E18B12543E': ('914f6f6e67591ac4d03baa5110c9c5322eec7ace16f311233bfe3f674d93a2bc', bytes.fromhex('bb24b87f4da609400b2d70490fbd18e9')), # prod
    'FBDF1AF71DD4DDDA': ('a24fad5785bd82f71b184100def10e56e9b239930ad06cfe677f6a8d692e452c', bytes.fromhex('97942399a2791462402630ed846d3a64')), # admin/prod
    '675B9C51B9352849': ('6e875d839cac95d7ce50da2270064752ebf7e248e3e71498bb7ce77986d3b359', bytes.fromhex('c418344d2d8f364e0b1f60c583d126d7')), # admin
    '3B2C4583A5C9E4EB': ('afb5ecfa91a03b73b336136ceddcaf993cce5d4e0ac4b80dfedc6c762f2a4698', bytes.fromhex('70cbe72a019394362f46372444fc68f9')), # admin
    '58B7CBFEC9E4BCE3': ('2f2aaee1e1a6874d574601e139128d3d08125ea72f5efe0d5c158016801aed57', bytes.fromhex('b56a23a57f5785ef2f767737ff0e79f4')), # admin
    '272FED81EAB31A41': ('ec68a60f87f44379980ae55af80aadf8a8cb75e8b2757b841dec69fcfdc83d4c', bytes.fromhex('e3c38d31c857e42c62aa250b61fb662e')), # admin
    '59BDD204AA7112ED': ('bfed24eb16bacb67a1dd90468223f35d5d5f751ca1f1323b7943918ca2b3ae18', bytes.fromhex('c370e96e49daefaa4b22784111c4dc79')), # admin
    '75EDFF360609C9F7': ('930e553d6a3920d05c99bc3111aaf288a94e7961b03e1914ca5bcda32ba9408c', bytes.fromhex('115e8adf8927887fe629bfd92829c11b')), # admin
}

from Crypto.Cipher import AES
from Crypto.Util import Counter
import os
import subprocess

for ident in files:
    fn, key = files[ident]
    if not fn or not key:
        continue
    if not os.path.isfile('%s.enc' % fn):
        subprocess.check_call(['wget', 'http://challenge2021.sstic.org:8080/files/%s.enc' % fn])
    if os.path.isfile('%s.bin' % fn):
        continue
    print("Decrypting file", fn)
    inf = open('%s.enc' % fn, 'rb')
    cipher = AES.new(key, mode=AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=1))
    with open('%s.bin' % fn, 'wb') as outf:
        outf.write(cipher.decrypt(inf.read()))
