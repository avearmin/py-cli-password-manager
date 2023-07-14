from cryptography.fernet import Fernet
import os, hashlib, json, base64


class PasswordVault:
    def __init__(self):
        """
        Initialize a PasswordVault object whose data members contain paths to
        where passwords and user information are stored.
        """
        self.user_info_path = os.path.join(os.getcwd(), "vault", "user_info.json")
        self.passwords_path = os.path.join(os.getcwd(), "vault", "passwords.json")

    def initialize_user(self):
        """
        Initialize user data used for validating master passwords and storing
        salt to generate derived keys for encryption/decryption.
        """
        data = self._get_json_data(self.user_info_path)
        master_password = input("Enter a Master Password:\n")
        data["hashed_master_pass"] = self.hash_master_password(master_password)
        data["salt"] = self.generate_salt()
        with open(self.user_info_path, "w") as json_file:
            json.dump(data, json_file, indent=4)

    def hash_master_password(self, master_password):
        """
        Hashes the master password for validation purposes using the sha3_256 algorithm.

        Parameters:
        - master_password (string): A string representation of an unhashed master password.

        Returns:
        - string: The hashed master password as a string.
        """
        encoded_password = master_password.encode()
        hashed_password = hashlib.sha3_256(encoded_password).digest()
        return hashed_password.decode("utf-16-be")

    def generate_salt(self):
        """
        Generate a random value (salt) used with the master password to generate a derived key
        for encryption/decryption.

        Returns:
        - string: The generated salt as a string.
        """
        return os.urandom(16).decode("utf-16-be")

    def write_password(self, master_password, service, password):
        """
        Write an encrypted password with its intended service to the json file.

        Parameters:
        - master_password(string): The master password used to validate access and encrypt the password.
        - service(string): The service the encrypted password will be paired with.
        - password(string): The password we wish to encrypt and write to the json file.
        """
        if (
            self.hash_master_password(master_password).encode("utf-16-be")
            == self._get_hashed_master_pass()
        ):
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._get_json_data(self.passwords_path)
            encrypted_password = self._encrypt_password(master_pass_key, password)
            data[service] = encrypted_password.decode("utf-8")
            with open(self.passwords_path, "w") as json_file:
                json.dump(data, json_file, indent=4)
        else:
            print("Invalid Master Password")

    def get_password(self, master_password, service):
        """
        Get and decrypt the desired password.

        Parameters:
        - master_password (string): The master password used to validate access and decrypt the password.
        - service (string): The service for which we want to retrieve and decrypt the password.
        """
        if (
            self.hash_master_password(master_password).encode("utf-16-be")
            == self._get_hashed_master_pass()
        ):
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._get_json_data(self.passwords_path)
            if service in data:
                encrypted_password = data[service]
                decryped_password = self._decrypt_password(
                    master_pass_key, encrypted_password
                )
                print(f"{service}: {decryped_password}")
        else:
            print("Invalid Master Password")

    def _get_master_pass_key(self, master_password, salt):
        """
        Generate the derived key using the master password and stored salt.

        Returns:
        - bytes: A URL-safe Base64 encoding of the derived key.
        """
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=master_password.encode(),
            salt=salt,
            iterations=100000,
            dklen=32,
        )
        return base64.urlsafe_b64encode(key)

    def _encrypt_password(self, master_pass_key, password_to_encrypt):
        """
        Encrypts the password using the provided master password key.

        Parameters:
        - master_pass_key (bytes): The derived key generated from the master password.
        - password_to_encrypt (string): The password to be encrypted.

        Returns:
        - string: The encrypted password as a string.
        """
        f = Fernet(master_pass_key)
        return f.encrypt(password_to_encrypt.encode("utf-8"))

    def _decrypt_password(self, master_pass_key, encrypted_password):
        """
        Decrypts the encrypted password using the provided master password key.

        Parameters:
        - master_pass_key (bytes): The derived key generated from the master password.
        - encrypted_password (string): The encrypted password as a string.

        Returns:
        - string: The decrypted password as a string.
        """
        f = Fernet(master_pass_key)
        return f.decrypt(encrypted_password).decode("utf-8")

    def _get_hashed_master_pass(self):
        """
        Retrieve the hashed master password from the user info.

        Returns:
        - bytes: The hashed master password.
        """
        data = self._get_json_data(self.user_info_path)
        return data["hashed_master_pass"].encode("utf-16-be")

    def _get_stored_salt(self):
        """
        Retrieve the stored salt from the user info.

        Returns:
        - bytes: The stored salt.
        """
        data = self._get_json_data(self.user_info_path)
        return data["salt"].encode("utf-16-be")

    def _get_json_data(self, path):
        """
        Retrieve JSON data from the specified path.

        Parameters:
        - path (string): The path to the JSON file.

        Returns:
        - dict: The JSON data.
        """
        if not os.path.exists(path):
            data = {}
        else:
            with open(path, "r") as json_file:
                data = json.load(json_file)
        return data
