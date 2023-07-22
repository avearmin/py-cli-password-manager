from cryptography.fernet import Fernet
import hashlib
import base64
import os


class PasswordEncrypter:
    """
    A class for handling password encryption and decryption.
    """
    @staticmethod
    def generate_salt(len: int=16) -> bytes:
        """
        Generate a random value (salt) used with the master password to generate a derived key
        for encryption/decryption.
        """
        return os.urandom(len)

    @staticmethod
    def add_salt(password: str, salt: bytes) -> str:
        """
        Add salt to the password.
        """
        salt_as_str = base64.b64encode(salt).decode()
        return password + salt_as_str

    @staticmethod
    def hash_master_password(master_password: str) -> bytes:
        """
        Hashes the master password for validation purposes using the sha3_256 algorithm.
        """
        encoded_password = master_password.encode()
        hashed_password = hashlib.sha3_256(encoded_password).digest()
        return hashed_password

    @staticmethod
    def get_master_pass_key(master_password: str, salt: bytes) -> bytes:
        """
        Generate the derived key using the master password and stored salt.
        """
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=master_password.encode(),
            salt=salt,
            iterations=100000,
            dklen=32,
        )
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt_password(
        master_pass_key: bytes, password_to_encrypt: str
    ) -> bytes:
        """
        Encrypts the password using the provided master password key.
        """
        f = Fernet(master_pass_key)
        return f.encrypt(password_to_encrypt.encode())

    @staticmethod
    def decrypt_password(
        master_pass_key: bytes, encrypted_password: bytes
    ) -> str:
        """
        Decrypts the encrypted password using the provided master password key.
        """
        f = Fernet(master_pass_key)
        return f.decrypt(encrypted_password).decode()
