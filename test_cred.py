from utils import *
from kmac import *
from cred import *
from zkp import *
from SUPItoSUCI import *
import decimal
import csv

def test_public_attributes():
    q = 3  # max number of attributes
    #public_m = [3] * q  # attributes
    public_m = [1, 100122, 99970]
    # attribute m_1 = payment validity (1 = bill paid)
    # attribute m_2 = time of expiration 10/01/2022
    # attributes m_3 = mcc(999) + mnc(70)
    params = setup()
    print("public attributes:", public_m)
    print("Payment Validity:",public_m[0])
    print("Time of expiration (mmddyy):", public_m[1])
    print("HN identifier - MCC(3-digit)+MNC(2-digit):", public_m[2])

    # generate key
    (iparams, sk) = cred_keygen(params, q)

    # credentials issuance
    #(u, u_prime, pi_issue), t_issue = blind_issue(params, sk, public_m=public_m)
    (u, u_prime, pi_issue) = blind_issue(params, sk, public_m=public_m)
    (u, u_prime) = blind_obtain(params, iparams, u, u_prime, pi_issue, public_m=public_m)

    # credentials showing
    (sigma, pi_show) = blind_show(params, iparams, (u, u_prime), public_m=public_m)
    #assert_blind_verify, t_verify = blind_verify(params, sk, iparams, sigma, pi_show)
    assert assert_blind_verify
    #return t_issue, t_verify


def test_private_attributes():
    q = 4 # max number of attributes
    private_m = [58610]   # concealed attribute MSIN SUPI(IMSI-Type= MCC|MNC|MSIN)
    public_m = [1, 100122, 99970]
    # attribute m_1 = payment validity (1 = bill paid)
    # attribute m_2 = time of expiration 10/01/2022
    # attributes m_3 = MCC(999) + MNC(70)
    print(f'1 private attribute [ECIES Scheme Output of SUPI(IMSI-Type)]: {str(private_m[0])}')
    print("public attributes:", public_m)
    params = setup()
    (d, gamma) = elgamal_keygen(params)  # El-Gamal keypair

    # generate key
    (iparams, sk) = cred_keygen(params, q)

    # prepare issuance
    (c, pi_prepare_issue) = prepare_blind_issue(params, gamma, private_m)

    # credentials issuance
    (u, u_prime_tilde, pi_issue, biparams), t_issue = blind_issue(params, sk, iparams, gamma, c, pi_prepare_issue,
                                                         public_m=public_m)
    (u, u_prime) = blind_obtain(params, iparams, u, u_prime_tilde, pi_issue, biparams=biparams, d=d,
                                gamma=gamma, c=c, public_m=public_m)

    # credentials showing
    start_time2= time.time()
    (sigma, pi_show) = blind_show(params, iparams, (u, u_prime), private_m=private_m, public_m=public_m)
    end_time2 = (time.time() - start_time2) * 1000
    print("(UE)Presentation Generation (blinded) Time -- %s ms ---" %  end_time2  )

    # credential verification
    start_time3 = time.time()
    # assert_blind_verify
    # assert_blind_verify, t_verify = blind_verify(params, sk, iparams, sigma, pi_show)
    assert blind_verify(params, sk, iparams, sigma, pi_show)

    t_verify = (time.time() - start_time3) * 1000
    print("(SN)Presentation Verification  Time --- %s ms ---" % t_verify)
    #t_end = time.time() - start_time
    #print()
    #print("(SN)Presentation Verification  Time --- %s seconds ---" % t_end)
   # return t_issue
    return t_issue, t_verify




if __name__ == '__main__':
    start_time1 = time.time()
    SUCI = toSUCI()
    t_end1 = (time.time() - start_time1) * 1000
    print()
    print("############SUCI CONCEALMENT ECIES SCHEME OUTPUT############")
    print("(UE) SUCI Concealment Computation Time --- %s ms---" % t_end1)
    # SUCI_ = unhexlify(SUCI)
    a = binascii.b2a_hex(SUCI)
    print(a)
    hexdump(SUCI)
    print()
    print("############Hidden Attributes Test###############")

    #t_pub_issue, t_pub_verify = test_public_attributes()
    #start_time = time.time()
    t_pri_issue, t_pri_verify = test_private_attributes()

    #t_end = (time.time() - start_time)*1000
    print()
    print("############UE Presentation Generation ##############")
    #print("(UE)Presentation Generation Time --- %s ms---" % t_end)

    #print("t_pub_issue, t_pub_verify:")
    #print(t_pub_issue, t_pub_verify)
    #print("t_pri_issue, t_pri_verify:")
    #print(t_pri_issue, t_pri_verify)
    print(f'###########5G Anonymous Authentication by Hexuan Yu###########')
    #time = [t_pri_issue, t_pri_verify]
    #with open('time.csv', 'a+', newline='') as f:
       # writer = csv.writer(f)
        # write the data
        #writer.writerow(time)



