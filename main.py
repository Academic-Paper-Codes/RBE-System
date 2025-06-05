import json
from TesRBE import *
from MRBE_P import *
from MTesRBE import *
from Improve_MTesRBE import *

# Simulated blockchain storage
class Blockchain:
    def __init__(self, filename="blockchain_data.json"):
        self.filename = filename
        self.chain = self.load_from_json()

    def add_block(self, data):
        block = {
            "index": len(self.chain) + 1,
            "data": self.serialize_data(data),
        }
        self.chain.append(block)

    def display_chain(self):
        print("\n=== Blockchain Storage ===")
        for block in self.chain:
            print(f"Block {block['index']}: {block['data']}")
        print("=========================")

    def save_to_json(self):
        with open(self.filename, "w") as json_file:
            json.dump(self.chain, json_file, indent=4)

    def load_from_json(self):
        try:
            with open(self.filename, "r") as json_file:
                content = json_file.read().strip()
                if not content:
                    print(f"File {self.filename} is empty. Initializing an empty blockchain.")
                    return []
                return json.loads(content)
        except FileNotFoundError:
            return []
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {self.filename}: {e}")
            return []

    @staticmethod
    def serialize_data(data):
        if isinstance(data, dict):
            return {key: Blockchain.serialize_data(value) for key, value in data.items()}
        elif isinstance(data, set):
            return list(data)
        elif isinstance(data, range):
            return list(data)
        elif callable(data):
            return str(data)
        elif isinstance(data, list):
            return [Blockchain.serialize_data(item) for item in data]
        elif isinstance(data, tuple):
            return [Blockchain.serialize_data(item) for item in data]
        else:
            return data

# Simple XOR Encryption/Decryption (for demonstration)
def xor_encrypt_decrypt(data, key):
    """
    A simple XOR encryption/decryption method.
    This can both encrypt and decrypt the data using the same key.
    """
    result = ''.join(chr(ord(c) ^ key) for c in data)
    return result

# Global blockchains
user_blockchain = Blockchain(filename="user_blockchain.json")
parameter_blockchain = Blockchain(filename="parameter_blockchain.json")

# Registered users storage
REGISTERED_USERS_FILE = "registered_users.json"

def load_registered_users():
    try:
        with open(REGISTERED_USERS_FILE, "r") as json_file:
            return json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_registered_user(uid, pkid):
    try:
        users = load_registered_users()

        if str(uid) in users:
            print(f"User ID {uid} is already registered. Skipping registration.")
            return False

        users[str(uid)] = pkid
        with open(REGISTERED_USERS_FILE, "w") as json_file:
            json.dump(users, json_file, indent=4)
        print(f"User {uid} with PK {pkid} registered successfully.")
        return True
    except Exception as e:
        print(f"Error saving registered user: {e}")
        return False

def display_registered_users():
    users = load_registered_users()
    if not users:
        print("No registered users found. Please register a user first.")
    else:
        print("\n=== Registered Users ===")
        for uid, pkid in users.items():
            print(f"User ID: {uid}, Public Key: {pkid}")
        print("=========================")

def is_user_registered(uid):
    users = load_registered_users()
    return str(uid) in users

# TokenGen and Check Implementation using modules
def perform_token_gen_and_check():
    print("\n=== Perform TokenGen and Check ===")
    try:
        uid = int(input("Enter User ID for TokenGen: "))
        skid = input("Enter User's Secret Key (skid): ")

        # 生成 token
        token = token_gen(uid, skid)
        print(f"Generated token: {token}")

        # 模拟 Web 3.0 服务提供方检查 token
        policy = "policy1"  # 假设的策略
        if check(policy, token):
            print("Token satisfies the policy. Token is valid.")
        else:
            print("Token does not satisfy the policy. Token is invalid.")

        # 根据策略生成密文并存储
        # raw_data = "Sensitive Data"
        # key = 123  # 假设的密钥，可以是任意整数
        # encrypted_data = xor_encrypt_decrypt(raw_data, key)

        # user_blockchain.add_block({
        #     "module": "TokenGen and Check",
        #     "policy": policy,
        #     "token": token,
        #     # "ciphertext": encrypted_data
        # })
        # print("Encrypted data has been added to the blockchain.")
        # print(f"Ciphertext (C): {encrypted_data} has been added to the blockchain.")
    except Exception as e:
        print(f"Error during TokenGen and Check: {e}")

def main():
    print("Welcome to our Web 3.0 Communications System")
    parameter_blockchain.display_chain()
    while True:
        try:
            user_id = int(input("Enter your User ID: "))
            if is_user_registered(user_id):
                print(f"Welcome back, User {user_id}!")
                break
            else:
                print(f"User ID {user_id} is not registered. Please register first.")
                register_new_user(None, None)
        except ValueError:
            print("Invalid User ID. Please enter an integer.")

    print("\nPlease choose which module you want to run:")
    print("1. TesRBE")
    # print("2. MRBE-P")
    print("2. MTesRBE*")
    print("3. MTesRBE*")

    try:
        choice = int(input("Enter the number of your choice (1-4): "))
        if choice == 1:
            module = MRBE(security_param=128, N=1000, n=10, nP=5)
            module_name = "TesRBE"
        # elif choice == 2:
        #     module = MRBE_P(lambda_param=16, N=100, n=10, nP=5)
        #     module_name = "MRBE-P"
        elif choice == 2:
            module = MRBEStar(security_param=128)
            module_name = "MTesRBE"
        elif choice == 3:
            module = MRBEStarP(security_param=128)
            module_name = "MTesRBE*"
        else:
            print("Invalid choice. Please restart and select a valid option.")
            return
    except ValueError:
        print("Invalid input. Please enter a number between 1 and 4.")
        return

    record_module_setup_to_parameter_blockchain(module, module_name)

    print(f"\nYou selected {module_name} module.")

    while True:
        print("\nOptions:")
        print("1. Register a new user")
        print("2. View registered users")
        print("3. Perform encryption")
        print("4. View user blockchain")
        print("5. View parameter blockchain")
        print("6. TokenGen and Check")
        print("7. Decrypt Data")
        print("0. Exit the system")
        try:
            action = int(input("Enter your choice (0-5): "))
            if action == 1:
                register_new_user(module, module_name)
            elif action == 2:
                display_registered_users()
            elif action == 3:
                perform_encryption(module_name)
            elif action == 4:
                user_blockchain.display_chain()
            elif action == 5:
                parameter_blockchain.display_chain()
            elif action == 6:
                perform_token_gen_and_check()
            elif action == 7:
                perform_decryption()
            elif action == 0:
                print("Exiting the system. Goodbye!")
                break
            else:
                print("Invalid action choice. Please enter 0, 1, 2, 3, 4, or 5.")
        except ValueError:
            print("Invalid input. Please enter a number (0-5).")

    user_blockchain.save_to_json()
    parameter_blockchain.save_to_json()

def perform_encryption(module_name):
    print("\n=== Perform Encryption ===")
    try:
        policy = input("Enter the access control policy (e.g., 'policy1'): ")
        nr = int(input("Enter the number of targeted receivers: "))
        raw_data = input("Enter the raw data to encrypt (m): ")

        # 加密
        key = 123
        encrypted_data = xor_encrypt_decrypt(raw_data, key)

        # 调试输出：查看加密前后的数据
        print(f"Original data: {raw_data}")
        print(f"Encrypted data: {encrypted_data}")

        # 将加密后的数据存储到区块链
        user_blockchain.add_block({
            "module": module_name,
            "policy": policy,
            "nr": nr,
            "ciphertext": encrypted_data
        })

        print("Encryption completed successfully.")
        print(f"Ciphertext (C) has been added to the blockchain.")

    except Exception as e:
        print(f"Error during encryption: {e}")


def perform_decryption():
    print("\n=== Perform Decryption ===")
    try:
        # 从区块链中获取密文
        latest_block = user_blockchain.chain[-1]['data']
        encrypted_data = latest_block.get('ciphertext', None)

        if not encrypted_data:
            print("No ciphertext found in the latest block!")
            return

        # 解密
        fixed_key = 123  # 固定密钥
        decrypted_data = xor_encrypt_decrypt(encrypted_data, fixed_key)

        # 调试输出：查看解密前后的数据
        print(f"Encrypted data: {encrypted_data}")
        print(f"Decrypted data: {decrypted_data}")

    except Exception as e:
        print(f"Error during decryption: {e}")

def record_module_setup_to_parameter_blockchain(module, module_name):
    try:
        crs = getattr(module, "crs", None)
        pp = getattr(module, "pp", None)
        aux = getattr(module, "aux", None)

        setup_data = {
            "module": module_name,
            "crs": crs,
            "pp": pp,
            "aux": aux
        }

        parameter_blockchain.add_block(setup_data)
        print(f"Module setup data for {module_name} recorded to parameter blockchain.")
    except Exception as e:
        print(f"Error recording module setup to parameter blockchain: {e}")

def register_new_user(module, module_name):
    print("\n=== Register New User ===")
    try:
        uid = int(input("Enter User ID: "))
        if is_user_registered(uid):
            print(f"User ID {uid} is already registered. Skipping registration.")
            return

        if module and hasattr(module, "key_gen"):
            skid, pkid, papid = module.key_gen(uid)
        elif module and hasattr(module, "key_gen_p"):
            skid, pkid, tid = module.key_gen_p(uid)
        else:
            pkid = f"GeneratedPK{uid}"  # 模拟生成一个默认公钥

        if save_registered_user(uid, pkid):
            user_blockchain.add_block({"module": module_name, "uid": uid, "pkid": pkid})
            print(f"User {uid} registered successfully in {module_name} module.")
    except ValueError:
        print("Invalid User ID. Please enter an integer.")
    except Exception as e:
        print(f"Error during registration: {e}")

def token_gen(uid, skid):
    """
    Generate the token T for the receiver based on uid and skid.
    The token is a combination of uid and skid, for example by simple concatenation.
    """
    token = f"{uid}-{skid}"
    return token

def check(policy, token):
    """
    A simplified Check function to ensure the receiver satisfies the policy.
    In real scenarios, the policy can be a complex structure and token checking would involve
    cryptographic checks.
    For now, let's assume the token is always valid (i.e., Check always returns True).
    """
    # In this example, we return True to simulate a valid check.
    return True

if __name__ == "__main__":
    main()
