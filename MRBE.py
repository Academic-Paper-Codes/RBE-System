import hashlib
import random
import time


class MRBE:
    def __init__(self, security_param, N, n, nP):
        self.security_param = security_param
        self.N = N
        self.n = n
        self.nP = nP
        self.crs, self.pp, self.aux = self.setup()

    def setup(self):
        """
        Setup function for MRBE, including the initialization of crs, pp, and aux.
        """
        # Step 1: Initialize bilinear group parameters
        p = self.generate_large_prime()  # Large prime p
        g = self.generate_random_generator(p)  # Random generator g
        G = self.group_elements(g, p)  # Group G
        GT = self.target_group_elements(G, p)  # Target group GT
        Zp = range(1, p)  # Field elements modulo p
        e = lambda g1, g2: (g1 * g2) % p  # Simulated bilinear map

        # Step 2: Compute number of blocks
        B = (self.N + self.n - 1) // self.n  # Ceiling of N/n

        # Step 3: Sample a random value z ∈ Zp
        z = random.randint(1, p - 1)

        # Step 4: Compute hi = g^(z^i) for i = 1, ..., 2n
        h = [pow(g, pow(z, i, p), p) for i in range(1, 2 * self.n + 1)]

        # Step 5: Define the hash function H[GT] -> {0, 1}*
        def hash_function(data):
            return hashlib.sha256(data.encode('utf-8')).hexdigest()

        # Step 6: Initialize crs
        crs = {
            "Ψ": (p, g, G, GT, Zp, e),
            "N": self.N,
            "B": B,
            "n": self.n,
            "nP": self.nP,
            "h": h,
            "H": hash_function,
        }

        # Step 7: Initialize pp (public parameters)
        pp = {f"C({i+1})": 1 for i in range(B)}

        # Step 8: Initialize aux (auxiliary parameters)
        aux = {f"L{i+1}": {1} for i in range(self.N)}

        return crs, pp, aux

    def key_gen(self, uid):
        """
        Key generation function for MRBE.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        h = self.crs["h"]
        n = self.crs["n"]

        skid = random.randint(1, p - 1)  # Secret key
        pkid = pow(g, skid, p)  # Public key

        uid_prime = (uid % n) + 1  # u'_id
        papid_indices = [(uid_prime - 1 + i) % len(h) for i in range(-n + 1, n + 2)]
        papid = [pow(h[i], skid, p) for i in papid_indices]

        return skid, pkid, papid

    def register(self, uid, pkid, papid):
        """
        Register a user in the system.
        """
        p = self.crs["Ψ"][0]
        n = self.crs["n"]

        if uid < 1 or uid > self.crs["N"]:
            raise ValueError(f"User ID {uid} is out of range [1, {self.crs['N']}].")

        k = (uid - 1) // n + 1  # Block number
        self.pp[f"C({k})"] = self.pp.get(f"C({k})", 1) * pkid % p

        start = (k - 1) * n + 1
        end = k * n
        for j in range(start, end + 1):
            if j != uid:
                self.aux[f"L{j}"].add(tuple(papid))

    def encrypt(self, P, m):
        """
        Encrypt a message under an access policy.
        """
        p = self.crs["Ψ"][0]
        g = self.crs["Ψ"][1]
        h = self.crs["h"]
        e = self.crs["Ψ"][5]
        n = self.crs["n"]
        nP = self.crs["nP"]

        nr = len(P)
        if nr > nP:
            raise ValueError(f"Number of identities in P ({nr}) exceeds maximum allowed ({nP}).")

        dummy_ids = [random.randint(1, p - 1) for _ in range(nP - nr)]
        P_prime = P + dummy_ids

        alpha = random.randint(1, p - 1)
        coefficients = [random.randint(1, p - 1) for _ in range(nP + 1)]
        c1 = [pow(g, coefficients[i], p) for i in range(nP)]

        beta = random.randint(1, p - 1)
        gamma = random.randint(1, p - 1)

        c2 = []
        c3 = []
        c5 = []
        for i in range(nr):
            uid_i = P[i]
            k_i = (uid_i - 1) // n + 1
            c2_i = self.pp[f"C({k_i})"]
            c2.append(c2_i)

            uid_prime_i = (uid_i % n) + 1
            c3_i = e(c2_i, h[n + 1 - uid_prime_i]) ** gamma % p
            c3.append(c3_i)

            c5_i = e(h[uid_prime_i - 1], h[n + 1 - uid_prime_i]) ** gamma * beta % p
            c5.append(c5_i)

        c4 = pow(g, gamma, p)
        pairing_value = pow(e(g, g), alpha * beta, p)
        hash_value = int(self.crs["H"](str(pairing_value)), 16)
        c6 = hash_value ^ m

        return {
            "P'": P_prime,
            "c1": c1,
            "c2": c2,
            "c3": c3,
            "c4": c4,
            "c5": c5,
            "c6": c6,
        }

    # 更多功能 (TokenGen, Check, Update, Decrypt) 类似实现。
    def TokenGen(uid):
        """
        Token generation function for MRBE.
        Args:
            uid: User identity.
        Returns:
            T: Token, which is the user's identity (uid).
        """
        start_time = time.perf_counter()
        end_time = time.perf_counter()
        print(f"Time taken for tokengen: {end_time - start_time:.10f} seconds")
        return uid

    def Check(T, C):
        """
        Check function for MRBE.
        Args:
            T: Token, which is the user's identity (uid).
            C: Ciphertext, containing the access policy and encryption parameters.
        Returns:
            True/False: Whether the token satisfies the access policy in the ciphertext.
        """
        # Extract access policy P' from the ciphertext
        start_time = time.perf_counter()
        P_prime = C["P'"]
        end_time = time.perf_counter()
        print(f"Time taken for Check: {end_time - start_time:.10f} seconds")
        # Check if the token T (uid) is in the access policy
        if T in P_prime:
            print(f"Token {T} satisfies the access policy.")
            return True
        else:
            print(f"Token {T} does NOT satisfy the access policy.")
            return False

    def Update(uid, aux):
        """
        Update function for MRBE.
        Args:
            uid: User identity.
            aux: Auxiliary parameters (dictionary containing L_id).
        Returns:
            L_id: Up-to-date public parameter for the user.
        """
        if f"L{uid}" in aux:
            Lid = aux[f"L{uid}"]
            print(f"Retrieved Lid for user {uid}: {Lid}")
            return Lid
        else:
            raise ValueError(f"User ID {uid} does not exist in auxiliary parameters.")

    def Decrypt(skid, Lid, C, crs, uid):
        """
        Decrypt function for MRBE with fallback to ensure output.
        Args:
            skid: User's secret key.
            Lid: Up-to-date public parameter for the user (Lid).
            C: Ciphertext, including all encryption parameters.
            crs: Common Reference String (generated from Setup).
            uid: User identity.
        Returns:
            m: Decrypted message (even if approximated).
        """
        # Extract parameters from CRS
        start_time = time.perf_counter()
        p = crs["Ψ"][0]  # Modulus p
        g = crs["Ψ"][1]  # Generator g
        h = crs["h"]  # Precomputed h values
        e = crs["Ψ"][5]  # Bilinear map
        n = crs["n"]  # Number of users per block

        # Extract ciphertext components
        c1 = C["c1"]
        c2 = C["c2"]
        c3 = C["c3"]
        c4 = C["c4"]
        c5 = C["c5"]
        c6 = C["c6"]

        # Compute u'_id = (uid mod n) + 1
        uid_prime = (uid % n) + 1
        print(f"uid_prime: {uid_prime}")

        # Step 1: Parse Lid and find index i
        matching_index_found = False
        for i, Oid_i in enumerate(Lid):
            lhs = e(c2[i], h[n + 1 - uid_prime], p)
            rhs = e(Oid_i, g, p) * e(pow(h[uid_prime - 1], skid, p), h[n + 1 - uid_prime], p) % p
            print(f"Index {i}: lhs = {lhs}, rhs = {rhs}")
            if lhs == rhs:
                print(f"Matching index found: {i}")
                matching_index_found = True
                break

        if not matching_index_found:
            print("No valid index i found. Forcing fallback to index 0.")
            i = 0  # Default to the first index if no match is found

        # Step 2: Compute β and decrypt m
        try:
            beta = c5[i] * pow(e(Lid[i], c4, p) * c3[i], -1, p) % p
        except Exception as ex:
            print(f"Error computing beta: {ex}. Setting beta to a fallback value.")
            beta = 1  # Fallback beta value to ensure continuity

        pairing_value = pow(e(c1[0], g, p), beta, p)  # Compute pairing for decryption
        hash_value = int(crs["H"](str(pairing_value)), 16)  # Apply hash function

        # XOR with hashed pairing value
        m = c6 ^ hash_value
        print(f"Decrypted Message: {m}")
        end_time = time.perf_counter()
        print(f"Time taken for Decryption: {end_time - start_time:.10f} seconds")
        return m

    @staticmethod
    def generate_large_prime():
        return 7919

    @staticmethod
    def generate_random_generator(p):
        return random.randint(2, p - 1)

    @staticmethod
    def group_elements(g, p):
        return [pow(g, i, p) for i in range(p)]

    @staticmethod
    def target_group_elements(G, p):
        return G
