import hashlib
import random
import time


class MRBEStar:
    def __init__(self, security_param):
        self.security_param = security_param
        self.crs = self.setup()
        self.PP = {}  # Public Parameters to store registered users

    def setup(self):
        """
        Setup algorithm for MRBE*.
        """
        p = self.generate_large_prime()
        g = self.generate_random_generator(p)
        G = self.group_elements(g, p)
        GT = self.target_group_elements(G, p)

        # Simulate bilinear map
        def bilinear_map(g1, g2):
            return (g1 * g2) % p

        # Hash function
        def hash_function(data):
            return hashlib.sha256(data.encode("utf-8")).hexdigest()

        # Placeholder encryption and decryption functions
        E = self.elgamal_encrypt
        D = self.elgamal_decrypt

        crs = {
            "Ψ": (p, g, G, GT, range(1, p), bilinear_map),
            "E": E,
            "D": D,
            "H": hash_function,
        }
        return crs

    def generate_large_prime(self):
        return 7919  # Replace with an actual large prime generator

    def generate_random_generator(self, p):
        return random.randint(2, p - 1)

    def group_elements(self, g, p):
        return [pow(g, i, p) for i in range(p)]

    def target_group_elements(self, G, p):
        return G

    def elgamal_encrypt(self, public_key, message, p):
        g = random.randint(2, p - 1)
        r = random.randint(1, p - 1)
        c1 = pow(g, r, p)
        c2 = (message * pow(public_key, r, p)) % p
        return c1, c2

    def elgamal_decrypt(self, private_key, ciphertext, p):
        c1, c2 = ciphertext
        s = pow(c1, private_key, p)
        s_inv = pow(s, -1, p)
        return (c2 * s_inv) % p

    def key_gen(self, uid):
        """
        Key generation function for MRBE*.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]

        skid = random.randint(1, p - 1)
        pkid = pow(g, skid, p)

        papid = {"uid": uid, "pkid": pkid}
        return skid, pkid, papid

    def register(self, uid, pkid):
        """
        Register function for MRBE*.
        """
        p = self.crs["Ψ"][0]

        if not (1 <= uid < p):
            raise ValueError(f"Invalid uid: {uid} is not in Zp.")

        if uid in self.PP:
            raise ValueError(f"uid: {uid} is already registered.")

        self.PP[uid] = pkid
        return True

    def encrypt(self, P, m):
        """
        Encrypt function for MRBE*.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        H = self.crs["H"]
        E = self.crs["E"]

        coefficients = [random.randint(1, p - 1) for _ in range(len(P) + 1)]
        c1 = [pow(g, alpha, p) for alpha in coefficients]

        beta = random.randint(1, p - 1)
        c2 = [E(self.PP[uid], beta, p) for uid in P]

        alpha_sum = sum(coefficients) % p
        pairing_value = self.crs["Ψ"][5](g, g) ** (alpha_sum * beta) % p
        c3 = int(H(str(pairing_value)), 16) ^ m

        return {"P": P, "c1": c1, "c2": c2, "c3": c3}

    def Tokengen(self, uid):
        """
        Token generation function for MRBE*.
        """
        return uid

    def check(self, T, C):
        """
        Check function for MRBE*.
        """
        P = C["P"]
        return T in P

    def decrypt(self, skid, Lid, C):
        """
        Decrypt function for MRBE*.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        D = self.crs["D"]
        H = self.crs["H"]

        P = C["P"]
        if Lid not in P:
            raise ValueError(f"User identity {Lid} not found in the access policy.")

        j = P.index(Lid)
        c2_j = C["c2"][j]

        beta = D(skid, c2_j, p)

        c1 = C["c1"]
        prod = 1
        for c1_i in c1:
            prod = (prod * self.crs["Ψ"][5](c1_i, g)) % p

        c3 = C["c3"]
        return c3 ^ int(H(str(prod)), 16)


# Example Usage
if __name__ == "__main__":
    mrbe_star = MRBEStar(security_param=128)

    # Key generation and registration
    uid1 = 123
    skid1, pkid1, papid1 = mrbe_star.key_gen(uid1)
    mrbe_star.register(uid1, pkid1)

    uid2 = 456
    skid2, pkid2, papid2 = mrbe_star.key_gen(uid2)
    mrbe_star.register(uid2, pkid2)

    # Encryption
    P = [123, 456]
    m = 42
    ciphertext = mrbe_star.encrypt(P, m)
    print("Ciphertext:", ciphertext)

    # Token generation and access check
    T = mrbe_star.token_gen(123)
    if mrbe_star.check(T, ciphertext):
        decrypted_message = mrbe_star.decrypt(skid1, 123, ciphertext)
        print("Decrypted message:", decrypted_message)
