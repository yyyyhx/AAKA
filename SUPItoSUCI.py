from cryptography.hazmat.primitives.asymmetric.x25519 import *
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#from sim import *
#from sim import IMSItoSUPI
from binascii import unhexlify
from hexdump import *
import sys
import time

backend = default_backend()

## CONSTANTS
# mode:
#  - testing
#  - ue: SUPI concealment

mode = "ue"

if mode == "testing":
  profileA = {
    "home_nw_private_key" : unhexlify("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d"), #this is unknown to the UE, stored at the home NW
    "home_nw_public_key" : unhexlify("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650"), #this is stored in the USIM, could be read from there
    "eph_private_key" : unhexlify("c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256"), #this shall be generated on the fly
    "eph_public_key" : unhexlify("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d"), #this is generated together with the private key
  }
elif mode == "network":
  profileA = {
    "home_nw_private_key" : unhexlify("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d"), #this is unknown to the UE, stored at the HN
    "home_nw_public_key" : unhexlify("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650"), #this is stored in the USIM, could be read from there
    "eph_private_key" : None, #unknown to the network
    "eph_public_key" : None, #should be extracted from the message
  }
elif mode == "ue":
  profileA = {
    "home_nw_private_key" : None, #this is unknown to the UE, stored at the home NW
    "home_nw_public_key" : unhexlify("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650"), #this is stored in the USIM, could be read from there
    #"home_nw_public_key" : None, #this is stored in the USIM, could be read from there
    "eph_private_key" : None, # should be generated
    "eph_public_key" : None
  }
else:
  print("Unknown mode , exiting.")
  sys.exit(1)

profileA.update(
  {
    "enckeylen" : 16, # AES-128 CTR
    "icblen" : 16, # AES IV
    "mackeylen" : 32, # HMAC-SHA256
    "maclen" : 8, # Truncating MAC output to n most significant bytes according to TS 33.501
    "shared_info2" : b""
  }
)

# PROFILE A - see 3GPP TS 33.501/Annex C.3.4.1 and Annex C.4.3
def profileA_conceal(SUPI):
  if mode == "testing":
    print("###### CONCEAL ##########")
    eph_private_key_obj = X25519PrivateKey.from_private_bytes(profileA["eph_private_key"])
  elif mode == "ue":
    start_time1 = time.time()
    eph_private_key_obj = X25519PrivateKey.generate()
    end_time1 = (time.time() - start_time1) * 1000
    print("(UE)DH Secret Key generation Time -- %s ms ---" % end_time1)
    print("###### UE side: profile A, SUPI Concealment ##########")
    profileA["eph_private_key"] = eph_private_key_obj.private_bytes(encoding=serialization.Encoding.Raw,
                                                                    format=serialization.PrivateFormat.Raw,
                                                                    encryption_algorithm=serialization.NoEncryption()
    )
    profileA["eph_public_key"] = eph_private_key_obj.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                               format=serialization.PublicFormat.Raw
    )
  else:
    print("Concealing when not in testing or UE mode is not supported, exiting.")
    sys.exit(1)

  home_nw_public_key_obj = X25519PublicKey.from_public_bytes(profileA["home_nw_public_key"])
  kdf_output_len = profileA["enckeylen"] + profileA["icblen"] + profileA["mackeylen"]

  # generating shared key via DH "exchange" shared secret without any exchange based on the
  # ephemeral key pair generated initially
  #   # -> in reality this is just preparing a from the elliptic curve + the stored HomeNW public key
  start_time2 = time.time()

  eph_shared_key = eph_private_key_obj.exchange(home_nw_public_key_obj)
  end_time2 = (time.time() - start_time2) * 1000
  print("(UE)DH shared session Key Ks generation Time -- %s ms ---" % end_time2)
  if mode == "testing":
    print("Ephemeral shared key after DH:")
    hexdump(eph_shared_key)
  xkdf = X963KDF(algorithm=hashes.SHA256(), length=kdf_output_len, sharedinfo=profileA["eph_public_key"], backend=backend)
  kdf_output = xkdf.derive(eph_shared_key)
  parameters = { "enckey" : kdf_output[:profileA["enckeylen"]],
                 "icb" : kdf_output[profileA["enckeylen"]:profileA["enckeylen"]+profileA["icblen"]],
                 "mackey" : kdf_output[-profileA["mackeylen"]:]
               }

  if mode == "testing":
    print()
    print("Encryption symmetric key and TS 33.501/Annex C.3.4 reference value:")
    hexdump(parameters["enckey"])
    hexdump(unhexlify('2ba342cabd2b3b1e5e4e890da11b65f6'))
    print()
    print("ICB and reference value:")
    hexdump(parameters["icb"])
    hexdump(unhexlify('e2622cb0cdd08204e721c8ea9b95a7c6'))
    print()
    print("MAC key and reference value:")
    hexdump(parameters["mackey"])
    hexdump(unhexlify('d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2'))

  cipher = Cipher(algorithms.AES(parameters["enckey"]), modes.CTR(parameters["icb"]), backend=backend)
  encryptor = cipher.encryptor()
  ct = encryptor.update(SUPI) + encryptor.finalize()
  h = hmac.HMAC(parameters["mackey"], hashes.SHA256(), backend=default_backend())
  h.update(ct+profileA["shared_info2"])
  mactag = h.finalize()[:profileA["maclen"]]
  final = profileA["eph_public_key"] + ct + mactag
  print (binascii.b2a_hex(final))

  if mode == "testing":
    print()
    print("Ciphered SUPI and reference value:")
    hexdump(ct)
    hexdump(unhexlify('cb02352410'))
    print()
    print("MAC tag and reference value:")
    hexdump(mactag)
    hexdump(unhexlify('cddd9e730ef3fa87'))
    print()
    print("Final output and reference value:")
    hexdump(final)
    #hexdump(unhexlify('b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87'))
    print("###### CONCEAL FINISHED ##########")
    print()
  return final


def profileA_deconceal(input):
  print("###### DECONCEAL ##########")
  home_nw_private_key_obj = X25519PrivateKey.from_private_bytes(profileA["home_nw_private_key"])
  eph_public_key = input[:32] #shortcut, should have calculated ceil((log2q)/8+1) = 32octets (q (The number of elements in the field Fq) = 2^255 - 19)
  mactag = input[-profileA["maclen"]:]
  ct = input[32:len(input)-profileA["maclen"]] # CipherText is in the middle between public key and MACtag
  eph_public_key_obj = X25519PublicKey.from_public_bytes(eph_public_key) #shortcut, should have calculated ceil((log2q)/8+1) = 32octets (q (The number of elements in the field Fq) = 2^255 - 19)
  kdf_output_len = profileA["enckeylen"] + profileA["icblen"] + profileA["mackeylen"]

  # generating shared key via DH "exchange"
  # -> in reality this is just preparing a shared secret without any exchange based on the
  # ephemeral key pair public key received + the stored HomeNW private key
  eph_shared_key = home_nw_private_key_obj.exchange(eph_public_key_obj)
  print("Ephemeral shared key after DH:")
  hexdump(eph_shared_key)
  xkdf = X963KDF(algorithm=hashes.SHA256(), length=kdf_output_len, sharedinfo=eph_public_key, backend=backend)
  kdf_output = xkdf.derive(eph_shared_key)
  parameters = { "enckey" : kdf_output[:profileA["enckeylen"]],
                 "icb" : kdf_output[profileA["enckeylen"]:profileA["enckeylen"]+profileA["icblen"]],
                 "mackey" : kdf_output[-profileA["mackeylen"]:]
               }
  print()
  print("Decryption symmetric key and TS 33.501/Annex C.3.4 reference value:")
  hexdump(parameters["enckey"])
  hexdump(unhexlify('2ba342cabd2b3b1e5e4e890da11b65f6'))
  print()
  print("ICB and reference value:")
  hexdump(parameters["icb"])
  hexdump(unhexlify('e2622cb0cdd08204e721c8ea9b95a7c6'))
  print()
  print("MAC key and reference value:")
  hexdump(parameters["mackey"])
  hexdump(unhexlify('d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2'))
  h = hmac.HMAC(parameters["mackey"], hashes.SHA256(), backend=default_backend())
  h.update(ct+profileA["shared_info2"])
  mactag = h.finalize()[:profileA["maclen"]]
  print()
  print("MAC tag and reference value:")
  hexdump(mactag)
  hexdump(unhexlify('cddd9e730ef3fa87'))
  cipher = Cipher(algorithms.AES(parameters["enckey"]), modes.CTR(parameters["icb"]), backend=backend)
  decryptor = cipher.decryptor()
  pt = decryptor.update(ct) + decryptor.finalize()
  print()
  print("Deciphered SUPI and reference value:")
  hexdump(pt)
  hexdump(unhexlify('00012080f6'))
  print("###### DECONCEAL FINISHED ##########")

def toSUCI(SUPI="058610", profile="A"):
  SUPI = unhexlify(SUPI)
  return profileA_conceal(SUPI)
  # returning the schemeOutput
  # suci-0(SUPI type)-mcc-mnc-routingIndentifier-protectionScheme-homeNetworkPublicKeyIdentifier-schemeOutput

def toSUPI(SUCI):
  profileA_deconceal(SUCI)

if __name__ == "__main__":
  start_time= time.time()
  x = hex(999700000058610)
  print("Hexdecimal value of SUPI:", x)
  SUCI = toSUCI()
  end_time = (time.time() - start_time) * 1000
  # print("(HN)SUCI Deconcealment Time -- %s ms ---" % end_time)
  print("(UE)SUCI Concealment Time -- %s ms ---" % end_time)
  """
  print("**********SUPI read from (U)SIM through PCSC_SCAN************") 
  IMSItoSUPI()
  """
  print("**********SUCI CONCEALMENT ECIES SCHEME OUTPUT************")
  #SUCI_ = unhexlify(SUCI)

  a = binascii.b2a_hex(SUCI)
  print(a)
  hexdump(SUCI)


  print(f'###########5G Anonymous Authentication by Hexuan Yu###########')

