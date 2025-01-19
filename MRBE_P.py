import random
import hashlib
import time


class MRBE_P:
    def __init__(self, lambda_param, N, n, nP):
        self.lambda_param = lambda_param
        self.N = N
        self.n = n
        self.nP = nP
        self.crs, self.pp, self.aux = self.setup()

    def setup(self):
        """
        Setup algorithm for MRBE-P.
        """
        p = 2 ** self.lambda_param - 1  # A Mersenne prime
        g = random.randint(2, p - 1)  # Generator of G
        Zp = list(range(1, p))  # Zp = {1, 2, ..., p-1}

        # Simplified bilinear map for testing
        def bilinear_map(x, y, p):
            return pow(x, y, p)

        z = random.randint(2, p - 1)
        h = [pow(g, pow(z, i, p), p) for i in range(1, self.N + 1) if i != self.n + 1]

        B = (self.N + self.n - 1) // self.n

        pp = [1] * B
        aux = [1 for _ in range(self.N)]

        def hash_function(value):
            return hash(value)

        crs = {
            "Ψ": (p, g, None, None, bilinear_map),
            "N": self.N,
            "B": B,
            "n": self.n,
            "nP": self.nP,
            "h": h,
            "H": hash_function,
        }

        return crs, pp, aux

    def keygen(self, uid):
        """
        KeyGen algorithm for MRBE-P.
        """
        p = self.crs["Ψ"][0]
        h = self.crs["h"]
        n = self.crs["n"]

        skid = random.randint(2, p - 1)
        u_prime_id = (uid % n) + 1
        pkid = pow(h[u_prime_id - 1], skid, p)

        papid = []
        for i in range(u_prime_id + n, n, -1):
            if i - 1 < len(h):
                papid.append(pow(h[i - 1], skid, p))
        papid.append(None)
        for i in range(n, u_prime_id, -1):
            if i - 1 < len(h):
                papid.append(pow(h[i - 1], skid, p))

        tid = random.randint(2, p - 1)
        return skid, pkid, papid, tid

    def register(self, uid, pkid, papid):
        """
        Register algorithm for MRBE-P.
        """
        p = self.crs["Ψ"][0]
        n = self.crs["n"]

        try:
            k = (uid - 1) // n + 1
            self.pp[k - 1] = (self.pp[k - 1] * pkid) % p

            u_prime_id = (uid % n) + 1
            for j in range((k - 1) * n + 1, k * n + 1):
                if j != uid:
                    index = j - (k - 1) * n - 1
                    if index < len(papid):
                        self.aux[j - 1] = (self.aux[j - 1] * papid[index]) % p
        except Exception as e:
            print(f"Error during registration: {e}")

    def encrypt(self, P, tids, message):
        """
        Encrypt algorithm for MRBE-P.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        h = self.crs["h"]
        nP = self.crs["nP"]

        updated_ids = [uid ^ tid for uid, tid in zip(P, tids)]
        nr = len(P)
        dummy_ids = [random.randint(2, p - 1) for _ in range(nP - nr)]
        P_prime = updated_ids + dummy_ids

        alpha = random.randint(2, p - 1)
        coefficients = [random.randint(1, p - 1) for _ in range(nP + 1)]
        c1 = [pow(g, coefficients[j], p) for j in range(nP + 1)]
        c7 = pow(g, alpha, p)

        beta = random.randint(2, p - 1)
        gamma = random.randint(2, p - 1)

        c2, c3, c5 = [], [], []
        for i, uid in enumerate(P):
            ki = (uid - 1) // self.crs["n"] + 1
            C_ki = self.pp[ki - 1]
            u_prime_id = (uid % self.crs["n"]) + 1

            c2.append(C_ki)
            c3_i = pow(C_ki, h[self.crs["n"] - u_prime_id], p) ** gamma % p
            c3.append(c3_i)
            c5_i = pow(h[uid - 1], h[self.crs["n"] - u_prime_id], p) ** beta % p
            c5.append(c5_i)

        c4 = pow(g, gamma, p)
        c6 = hashlib.sha256(str(pow(g, alpha * beta, p)).encode()).hexdigest()
        c6 = int(c6, 16) ^ int.from_bytes(message.encode("utf-8"), "big")

        return {
            "P_prime": P_prime,
            "c1": c1,
            "c2": c2,
            "c3": c3,
            "c4": c4,
            "c5": c5,
            "c6": c6,
            "c7": c7,
        }

    def Tokengen(self, uid, tid):
        """
        TokenGen algorithm for MRBE-P.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        nP = self.crs["nP"]

        t = random.randint(2, p - 1)
        t1 = pow(g, t, p)
        t2 = [pow(g, (uid ^ tid) ** i, p) for i in range(nP + 1)]

        return {"t1": t1, "t2": t2}

    def decrypt(self, skid, Lid, C):
        """
        Decrypt algorithm for MRBE-P.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]

        beta = skid
        e_c7_g_beta = pow(C["c7"], beta, p)
        hashed_value = hashlib.sha256(str(e_c7_g_beta).encode()).hexdigest()
        hashed_int = int(hashed_value, 16)

        m = C["c6"] ^ hashed_int
        return m


# Example Usage
if __name__ == "__main__":
    # Initialize system
    mrbe_p = MRBE_P(lambda_param=16, N=100, n=10, nP=5)

    # Key generation
    uid = 42
    skid, pkid, papid, tid = mrbe_p.keygen(uid)

    # Registration
    mrbe_p.register(uid, pkid, papid)

    # Encryption
    P = [10, 20, 30, 42]
    tids = [15, 25, 35, tid]
    message = "Hello, MRBE-P!"
    ciphertext = mrbe_p.encrypt(P, tids, message)

    # Decryption
    decrypted_message = mrbe_p.decrypt(skid, None, ciphertext)
    print("Decrypted message:", decrypted_message)
