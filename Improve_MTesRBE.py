import hashlib
import random
import time


class MRBEStarP:
    def __init__(self, security_param):
        self.security_param = security_param
        self.crs = self.setup_p()
        self.PP = {}  # Public parameters for registered users
        self.tids = {}  # Temporary identities for users

    def setup_p(self):
        """
        Setup function for MRBE*-P.
        """
        p = self.generate_large_prime()
        g = self.generate_random_generator(p)
        G = self.group_elements(g, p)
        GT = self.target_group_elements(G, p)

        def bilinear_map(g1, g2):
            return (g1 * g2) % p

        def hash_function(data):
            return hashlib.sha256(data.encode("utf-8")).hexdigest()

        return {
            "Ψ": (p, g, G, GT, range(1, p), bilinear_map),
            "E": self.elgamal_encrypt,
            "D": self.elgamal_decrypt,
            "H": hash_function,
        }

    def generate_large_prime(self):
        return 7919  # Replace with actual prime generation

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

    def key_gen_p(self, uid):
        """
        Key generation for MRBE*-P.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]

        skid = random.randint(1, p - 1)
        pkid = pow(g, skid, p)
        tid = random.randint(1, p - 1)

        self.tids[uid] = tid
        return skid, pkid, tid

    def register_p(self, uid, pkid):
        """
        Register function for MRBE*-P.
        """
        if uid in self.PP:
            raise ValueError(f"User ID {uid} is already registered.")

        self.PP[uid] = pkid

    def encrypt_p(self, P, m):
        """
        Encrypt function for MRBE*-P.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        H = self.crs["H"]
        E = self.crs["E"]
        e = self.crs["Ψ"][5]

        coefficients = [random.randint(1, p - 1) for _ in range(len(P) + 1)]
        c1 = [pow(g, alpha, p) for alpha in coefficients]

        beta = random.randint(1, p - 1)
        c2 = [E(self.PP[uid], beta, p) for uid in P]

        alpha_sum = sum(coefficients) % p
        c4 = pow(g, alpha_sum, p)

        pairing_value = pow(e(g, g), alpha_sum * beta, p)
        c3 = int(H(str(pairing_value)), 16) ^ m

        return {"P": P, "c1": c1, "c2": c2, "c3": c3, "c4": c4}

    def Tokengen(self, uid):
        """
        Token generation for MRBE*-P.
        """
        if uid not in self.tids:
            raise ValueError(f"User ID {uid} has no temporary identity.")

        tid = self.tids[uid]
        t1 = uid ^ tid
        t2 = tid
        return t1, t2

    def check_p(self, T, C):
        """
        Check function for MRBE*-P.
        """
        t1, t2 = T
        P = C["P"]
        return any((uid ^ t2) == t1 for uid in P)

    def decrypt_p(self, skid, Lid, C):
        """
        Decrypt function for MRBE*-P.
        """
        p = self.crs["Ψ"][0]
        e = self.crs["Ψ"][5]
        H = self.crs["H"]
        D = self.crs["D"]

        P = C["P"]
        if Lid not in P:
            raise ValueError(f"User identity {Lid} not found in access policy.")

        j = P.index(Lid)
        c2_j = C["c2"][j]
        beta = D(skid, c2_j, p)

        c4 = C["c4"]
        pairing_value = pow(c4, beta, p)
        c3 = C["c3"]
        return c3 ^ int(H(str(pairing_value)), 16)


# Example Usage
if __name__ == "__main__":
    mrbe_star_p = MRBEStarP(security_param=128)

    # Key generation and registration
    uid1 = 123
    skid1, pkid1, tid1 = mrbe_star_p.key_gen_p(uid1)
    mrbe_star_p.register_p(uid1, pkid1)

    uid2 = 456
    skid2, pkid2, tid2 = mrbe_star_p.key_gen_p(uid2)
    mrbe_star_p.register_p(uid2, pkid2)

    # Encryption
    P = [123, 456]
    m = 42
    ciphertext = mrbe_star_p.encrypt_p(P, m)
    print("Ciphertext:", ciphertext)

    # Token generation and access check
    T = mrbe_star_p.token_gen_p(123)
    if mrbe_star_p.check_p(T, ciphertext):
        decrypted_message = mrbe_star_p.decrypt_p(skid1, 123, ciphertext)
        print("Decrypted message:", decrypted_message)
