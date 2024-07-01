""" credential scheme based on keyed mac """
from petlib.ec import EcGroup
from kmac import setup as setup_ggm
from kmac import keygen as ggm_keygen
from kmac import mac as ggm_mac
from utils import *
from zkp import *
import time
import csv

def setup():
    """ generate all public parameters """
    return setup_ggm()


def cred_keygen(params, q):
    """ credential keygen """
    assert q > 0
    (G, o, g, h) = params
    (x, X) = ggm_keygen(params, q)
    x0_tilde = o.random()
    Cx0 = x[0] * g + x0_tilde * h
    iparams = (Cx0, X)
    sk = (x, x0_tilde)
    return (iparams, sk)


def prepare_blind_issue(params, gamma, private_m):
    """ prepare issuance of credentials """

    assert gamma and len(private_m) > 0
    (G, o, g, h) = params
    enc = [elgamal_enc(params, gamma, m, g) for m in private_m]
    (a, b, k) = zip(*enc)
    c = list(zip(a, b))
    pi_prepare_issue = make_pi_prepare_issue(params, gamma, c, k, private_m)
    return (c, pi_prepare_issue)


def blind_issue(params, sk, iparams=None, gamma=None, c=[], pi_prepare_issue=None, public_m=[]):
    """ issue credentials """

    assert len(c) + len(public_m) > 0
    (G, o, g, h) = params
    (x, x0_tilde) = sk
    assert x0_tilde and len(x) > len(c) + len(public_m)

    ## mixed public / private attributes
    if len(c):

        assert iparams and gamma and pi_prepare_issue
        assert verify_pi_prepare_issue(params, gamma, c, pi_prepare_issue)
        (Cx0, X) = iparams
        (enc_a, enc_b) = zip(*c)
        # blinding factors
        b = o.random()
        u = b * g
        bx0_tilde = b * x0_tilde % o
        bx = [b * xi % o for xi in x]
        bCx0 = b * Cx0
        bX = [b * Xi for Xi in X]
        bsk = (bx, bx0_tilde)
        biparams = (bCx0, bX)
        # create credential over encrypted attributes
        start_time = time.time()
        r = o.random()
        t1 = [mi * g for mi in public_m]
        t2 = r * g + ec_sum([bxi * enc_ai for (bxi, enc_ai) in zip(bx[1:], enc_a)])
        t3 = r * gamma + bx[0] * g + ec_sum([bxi * enc_bi for (bxi, enc_bi) in zip(bx[1:], list(enc_b) + t1)])
        u_prime = (t2, t3)

        pi_issue = make_pi_issue(params, sk, iparams=iparams, gamma=gamma, c=c, b=b, bsk=bsk, r=r, public_m=public_m)
        print()
        t_start = (time.time() - start_time)*1000
        print("(HN)credentials issuance Execution Time --- %s ms---" % t_start)
        print("Issued credentials:", pi_issue)
        return (u, u_prime, pi_issue, biparams), t_start

    ## only public attributes
    else:
        (u, u_prime) = ggm_mac(params, x, public_m)
        pi_issue = make_pi_issue(params, sk, u=u, public_m=public_m)
        return (u, u_prime, pi_issue), -1


def blind_obtain(params, iparams, u, u_prime, pi_issue, biparams=None, d=None, gamma=None, c=[], public_m=[]):
    """ verify credentials issuance """
    assert len(c) + len(public_m) > 0
    # verify proof of issuance
    start_time4 = time.time()
    assert verify_pi_issue(params, iparams, u, u_prime, pi_issue, biparams=biparams, gamma=gamma,
                           ciphertext=c, public_m=public_m)
    t_start4 = (time.time() - start_time4) * 1000
    print("(UE)credentials Obtain Verification Execution Time --- %s ms---" % t_start4)
    if len(c):
        return (u, elgamal_dec(d, u_prime))
    else:
        return (u, u_prime)


def blind_show(params, iparams, cred, private_m=[], public_m=[]):
    """ show credentials """
    #start_time = time.time()
    attributes = private_m + public_m
    assert cred and len(attributes) > 0
    (G, o, g, h) = params
    (u0, u0_prime) = cred
    assert u0 and u0_prime
    # randomize credentials
    a = o.random()
    (u, u_prime) = (a * u0, a * u0_prime)
    # form commitments
    r = o.random()
    z = [o.random() for _ in attributes]
    Cm = [mi * u + zi * h for (mi, zi) in zip(attributes, z)]
    Cu_prime = u_prime + r * g
    sigma = (u, Cm, Cu_prime)
    pi_show = make_pi_show(params, iparams, attributes, r, z, u_prime, sigma)
    print()
    #print("(UE)Presentation Generation (blinded) Time -- %s seconds ---" % (time.time() - start_time))
    print("Credential Presentation:", pi_show)
    return (sigma, pi_show)


def blind_verify(params, sk, iparams, sigma, pi_show):
    """ verify credentials """

    assert iparams and sigma and pi_show
    (x, _) = sk
    (u, Cm, Cu_prime) = sigma
    assert u and len(Cm) > 0 and Cu_prime
    V = x[0] * u + ec_sum([xi * Cmi for (xi, Cmi) in zip(x[1:], Cm)]) - Cu_prime

    print()

    print("Presentation Verification:", V)
   # return  verify_pi_show(params, iparams, sigma, pi_show, V), t_end
    return verify_pi_show(params, iparams, sigma, pi_show, V)





