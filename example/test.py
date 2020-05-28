'''import ecdsa
from hashlib import sha256

message = b"hello tss"
public_key = '683a0bcf8af0a47f20155cb3bd194b090e6a7a3a932b333850b28bf84b5e7bc93397f59feacc98ce8768468aa91862eb2001c846c35c7781dd8dd7c7b0d154cf' # Prima hex poi conc
#public_key1 = '5a03109590b80d5fc9262185f93a160e2ebe0334cbd2bae9482e0726699906170b0daf2151eda16cd9010c74370e0ee3f34385ed829c1781dd8dd7c7b0d154cf' # Prima conc poi hex

sig = '3da3273d24ddd159a8a33dd5038d281bcad357ac48affc9adcd66bf03139087b39076d171e1c5388301289543ee7e281382a786bf8c8962667fe82704f1e176b' #prima Hex poi conc
sig1 = '353b248a4f8ba5ecc6349a599f66b0ac4f5c7249504ad7f1d6a7cf0b1ad08b049f4594594f1a275a54c5b4a1042fe4dd309d707fe7fb762667fe82704f1e176b'
sig2 = 'f165da8f3800712b273c487175ff09148469a59cc89c9a4bf59273348360c910267efa8cfe2220bb7dc34f9ed6c6b13c18f4362a105cf6c1cff74e3540da73ea'
       #'3045022100971dcea75a17ac500fe7b8c27e74eac91ab2baab822472163b2ca21480fe8cce02207171955ce2665bdc5db57520955d1ea01b434b4cf6e3891d283d98d9ad62e856'
vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP348k1, hashfunc=sha348) # the default is sha1
vk.verify(bytes.fromhex(sig2), message) # True
'''

'''
\x30\x82\x01\xe1\xa0\x03\x02\x01\x02\x02\x14\x65\x09\x56\xd9\xc8\xd4\x04\xcd\x4c\x3f\xca\xd5\xff\x70\x46\x0b\xe4\x61\x64\x68\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x68\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x13\x0e\x4e\x6f\x72\x74\x68\x20\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x13\x0b\x48\x79\x70\x65\x72\x6c\x65\x64\x67\x65\x72\x31\x0f\x30\x0d\x06\x03\x55\x04\x0b\x13\x06\x46\x61\x62\x72\x69\x63\x31\x19\x30\x17\x06\x03\x55\x04\x03\x13\x10\x66\x61\x62\x72\x69\x63\x2d\x63\x61\x2d\x73\x65\x72\x76\x65\x72\x30\x1e\x17\x0d\x32\x30\x30\x35\x31\x33\x31\x31\x32\x39\x30\x30\x5a\x17\x0d\x32\x31\x30\x35\x31\x33\x31\x31\x33\x34\x30\x30\x5a\x30\x5d\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x08\x13\x0e\x4e\x6f\x72\x74\x68\x20\x43\x61\x72\x6f\x6c\x69\x6e\x61\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x13\x0b\x48\x79\x70\x65\x72\x6c\x65\x64\x67\x65\x72\x31\x0f\x30\x0d\x06\x03\x55\x04\x0b\x13\x06\x63\x6c\x69\x65\x6e\x74\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x13\x05\x61\x64\x6d\x69\x6e\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x11\x63\x01\x77\x06\xce\x3f\x89\x12\x21\x2d\x59\x8c\x06\xe5\xd8\x98\x0f\x71\xc8\xef\x4b\xc2\xdb\x3e\xad\xcb\xd4\x1b\xd9\x90\xac\x47\x50\x90\xf4\x25\x8f\x7c\x59\x8b\x21\x81\xcf\xf7\xe1\x00\x92\x4f\x6a\xde\x60\x28\xb2\x66\xc1\xe5\x26\x33\x54\x6a\x5d\x0b\x1f\xa3\x74\x30\x72\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x80\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x79\xb1\xa9\xd8\xc0\x7d\x4e\x64\xc2\xa1\x29\x81\x31\x8c\x88\xa3\xc5\x33\x25\x57\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\xf7\xc9\x1f\x77\xa6\x4a\x66\x90\xba\xa7\x01\x9a\x19\x95\x56\xcb\x24\xee\x16\x7b\x30\x12\x06\x03\x55\x1d\x11\x04\x0b\x30\x09\x82\x07\x6f\x6c\x79\x6d\x70\x75\x73
'''


from M2Crypto import X509, EC, EVP
from hashlib import sha256
from pyasn1_modules.rfc2314 import Signature
from pyasn1_modules.rfc2459 import Certificate
from pyasn1.codec.der import encoder, decoder
from base64 import *
import binascii

cert = X509.load_cert('cert.pem')
#ca_pkey = EVP.load_key('rsa.private')

asn1_cert = decoder.decode(cert.as_der(), asn1Spec=Certificate())[0]
#tbs = asn1_cert.getComponentByName("tbsCertificate")
#print(tbs)
#tbs_der = encoder.encode(tbs)

#print(cert.as_text())

#digest = sha256()
#digest.update(tbs_der)
#signature = ca_pkey.get_rsa().sign(digest.digest(), "sha256")

#print(bin(signature))

#print(asn1_cert.getComponentByName("signatureValue"),'\n\n\n\n')
#print(signature)
#print(cert.as_text())
#print(asn1_cert)
# Take the raw signature and turn it into a BitString representations (special thanks to Alex <ralienpp@gmail.com>)
bin_signature = Signature(0x3045022100ff169bf8d012e1c84d5e55c029f77e9ad27e31925500cbd7335550d980dea8f502201497db4435963c33d018ccc15ab2ef815cad38ae5221ed8ca83f1264c9ea182e)

#asn1_cert.setComponentByName("signatureValue", Signature(str(bin(0x3045022100ff169bf8d012e1c84d5e55c029f77e9ad27e31925500cbd7335550d980dea8f502201497db4435963c33d018ccc15ab2ef815cad38ae5221ed8ca83f1264c9ea182e))))#0xff169bf8d012e1c84d5e55c029f77e9ad27e31925500cbd7335550d980dea8f51497db4435963c33d018ccc15ab2ef815cad38ae5221ed8ca83f1264c9ea182e)
print(asn1_cert.getComponentByName("signatureValue"))
print("00"+bin(0x3045022100ff169bf8d012e1c84d5e55c029f77e9ad27e31925500cbd7335550d980dea8f502201497db4435963c33d018ccc15ab2ef815cad38ae5221ed8ca83f1264c9ea182e)[2:])
asn1_cert.setComponentByName("signatureValue","00"+bin(0x3045022100ff169bf8d012e1c84d5e55c029f77e9ad27e31925500cbd7335550d980dea8f502201497db4435963c33d018ccc15ab2ef815cad38ae5221ed8ca83f1264c9ea182e)[2:])

f = open("test.der", "wb")
f.write(encoder.encode(asn1_cert))
f.close()

#print(asn1_cert)
# Check that both certificates matches
#cert.sign(ca_pkey, md='sha256')
#print(cert.as_text())
#print((encoder.encode(asn1_cert.as_der())).as_text())
#print(cert.as_text())

#print (encoder.encode(asn1_cert).verify())
