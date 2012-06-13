""" 
Waters - Identity-based signatures

| From: "B. Waters - Efficient identity-based encryption without random oracles"
| Published in: EUROCRYPT 2005
| Available from: Vol 3494 of LNCS, pages 320-329
| Notes: 

* type:           signature (ID-based)
* setting:        bilinear groups (asymmetric)

:Authors:    J. Ayo Akinyele
:Date:       11/2011
"""
from toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from toolbox.iterate import dotprod
from toolbox.hash_module import Waters

debug = False
class WatersSig:
    def __init__(self, groupObj):
        global group,lam_func
        group = groupObj
        lam_func = lambda i,a,b: a[i] ** b[i]

    def setup(self, z, l=32):
        global waters
        waters = Waters(group, z, l)
        alpha, h = group.random(ZR), group.random(G1)
        g1, g2 = group.random(G1), group.random(G2)
        A = pair(h, g2) ** alpha
        y = [group.random(ZR) for i in range(z)]
        y1t,y2t = group.random(ZR), group.random(ZR)

        u1t = g1 ** y1t; u2t = g1 ** y2t
        u = [g1 ** y[i] for i in range(z)]

        u1b = g2 ** y1t; u2b = g2 ** y2t
        ub =[g2 ** y[i] for i in range(z)]

        msk = h ** alpha
        mpk = {'g1':g1, 'g2':g2, 'A':A, 'u1t':u1t, 'u2t':u2t, 'u':u, 'u1b':u1b, 'u2b':u2b, 'ub':ub, 'z':z, 'l':l } 
        return (mpk, msk) 

    def keygen(self, mpk, msk, ID):
        if debug: print("Keygen alg...")
        k = waters.hash(ID) # return list from k1,...,kz
        if debug: print("k =>", k)
        r = group.random(ZR)
        k1 = msk * ((mpk['u1t'] * dotprod(group.init(G1), -1, mpk['z'], lam_func, mpk['u'], k)) ** r)  
        k2 = mpk['g1'] ** -r
        return (k1, k2)
    
    def sign(self, mpk, sk, M):
        if debug: print("Sign alg...")
        m = waters.hash(M) # return list from m1,...,mz
        if debug: print("m =>", m)
        (k1, k2) = sk
        s  = group.random(ZR)
        S1 = k1 * ((mpk['u2t'] * dotprod(group.init(G1), -1, mpk['z'], lam_func, mpk['u'], m)) ** s)
        S2 = k2
        S3 = mpk['g1'] ** -s
        return {'S1':S1, 'S2':S2, 'S3':S3}
    
    def verify(self, mpk, ID, M, sig):
        if debug: print("Verify...")
        k = waters.hash(ID)
        m = waters.hash(M)
        (S1, S2, S3) = sig['S1'], sig['S2'], sig['S3']
        A, g2 = mpk['A'], mpk['g2']
        comp1 = dotprod(group.init(G2), -1, mpk['z'], lam_func, mpk['ub'], k)
        comp2 = dotprod(group.init(G2), -1, mpk['z'], lam_func, mpk['ub'], m)
        if (pair(S1, g2) * pair(S2, mpk['u1b'] * comp1) * pair(S3, mpk['u2b'] * comp2)) == A: 
            return True
        return False

def main():
   z = 5
   groupObj = PairingGroup('SS512')

   waters = WatersSig(groupObj)
   (mpk, msk) = waters.setup(z)

   ID = 'janedoe@email.com'
   sk = waters.keygen(mpk, msk, ID)  
   if debug:
    print("Keygen...")
    print("sk =>", sk)
 
   M = 'please sign this new message!'
   sig = waters.sign(mpk, sk, M)
   if debug: print("Signature...")

   assert waters.verify(mpk, ID, M, sig), "invalid signature!"
   if debug: print("Verification successful!")

if __name__ == "__main__":
    debug = True
    main()