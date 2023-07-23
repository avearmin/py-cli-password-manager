from password_encryption import PasswordEncrypter
from password_generator import PasswordGenerator
from password_validation import PasswordValidator
import os, pickle, pyperclip


class PasswordVault:
    """
    A class to securely manage and store encrypted passwords.
    """
    
    # --- Constructors and Initialization Methods ---
    
    def __init__(self):
        """
        Initialize a PasswordVault object whose data members contain paths to
        where passwords and user information are stored.
        """
        self.user_info_path = os.path.join(os.getcwd(), "user_info.bin")
        self.passwords_path = os.path.join(os.getcwd(), "passwords.bin")

    def initialize_user(self):
        """
        Initialize user data used for validating master passwords and storing
        salt to generate derived keys for encryption/decryption.
        """
        min_pass_len = 12
        print(
            "Create a master password with at least:\n"
            + f"{min_pass_len} characters, 1 uppercase, 1 lowercase "
            + "1 number, and 1 special character"
        )

        master_password = self._wait_for_validated_password(min_pass_len)
        salt = PasswordEncrypter.generate_salt()
        salted_master_password = PasswordEncrypter.add_salt(master_password, salt)
        self._save_user_info(salted_master_password, salt)
        print("Master password, and salt have been successfully saved.")
    
    # --- Utility Methods for Data Manipulation ---
    
    def _load_data_from_file(self, path: str) -> dict:
        """
        Retrieve and unpickle data from the specified file.
        """
        if not os.path.exists(path):
            data = {}
        else:
            with open(path, "rb") as file:
                data = pickle.load(file)
        return data
        
    def _save_user_info(salted_master_password: str, salt: bytes):
        """
        Save the hashed master password, and salt to data.
        """
        data = self._load_data_from_file(self.user_info_path)
        data["salt"] = salt
        data["master_pass"] = PasswordEncrypter.hash_master_password(
            salted_master_password
        )
        with open(self.user_info_path, "wb") as file:
            pickle.dump(data, file)
    
    def _save_encrypted_password(self, service: str, encrypted_password: bytes):
        """
        Save the encrypted password for the given service from data.
        """
        data = self._load_data_from_file(self.passwords_path)
        data[service] = encrypted_password
        with open(self.passwords_path, "wb") as file:
            pickle.dump(data, file)
            
    def _load_encrypted_password(self, service: str) -> str or None:
        """
        Load the encrypted password for the given service from data.
        """
        data = self._load_data_from_file(self.passwords_path)
        if service in data:
            return data[service]
            
    def _load_master_pass_from_data(self) -> bytes:
        """
        Retrieve the hashed master password from the user info.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["master_pass"]

    def _load_salt_from_data(self) -> bytes:
        """
        Retrieve the stored salt.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["salt"]

    # --- Password Management Methods ---
    
    def _encrypt_password(
        self, master_password: str, unencrypted_password: str
    ) -> bytes:
        """
        Encrypt the given encrypted password using the master password.
        """
        salt = self._load_salt_from_data()
        master_pass_key = PasswordEncrypter.get_master_pass_key(master_password, salt)
        encryped_password = PasswordEncrypter.encrypt_password(
            master_pass_key, unencrypted_password
        )
        return encryped_password
        
    def _decrypt_password(self, master_password: str, encrypted_password: bytes) -> str:
        """
        Decrypt the given encrypted password using the master password.
        """
        salt = self._load_salt_from_data()
        master_pass_key = PasswordEncrypter.get_master_pass_key(master_password, salt)
        decryped_password = PasswordEncrypter.decrypt_password(
            master_pass_key, encrypted_password
        )
        return decryped_password
    
    def _wait_for_validated_password(self, min_pass_len) -> str:
        """
        Continuously prompt the user until a validated password can be returned.
        """
        min_upper = 1
        min_lower = 1
        min_num = 1
        min_special = 1
        while True:
            password = input()
            validator = PasswordValidator(
                min_pass_len, min_upper, min_lower, min_num, min_special
            )
            is_password_valid = validator.validate(password)
            if is_password_valid:
                return password
            print(
                "Requirements not met. You need at least:\n"
                + f"{min_pass_len} characters, 1 uppercase, 1 lowercase, "
                + "1 number, and 1 special character"
            )
            
    # --- Password Operations Methods ---

    def write_password(self, master_password: str, service: str):
        """
        Write an encrypted password with its intended service to the file.
        """
        master_pass_is_correct = self._verify_master_password(master_password)
        if master_pass_is_correct:
            min_pass_len = 8
            print(
                "Create a password with at least:\n"
                + f"{min_pass_len} characters, 1 uppercase, 1 lowercase "
                + "1 number, and 1 special character"
            )
            password = self._wait_for_validated_password(min_pass_len)
            encrypted_password = self._encrypt_password(master_password, password)
            self._save_encrypted_password(service, encrypted_password)
            print(f"a password for {service} has been successfully saved.")
        else:
            print("Invalid Master Password")

    def write_generated_password(self, master_password: str, service: str):
        """
        Write an encrypted randomly generated password with its intended service to the file.
        """
        master_pass_is_correct = self._verify_master_password(master_password)
        if master_pass_is_correct:
            password_length = 20
            generator = PasswordGenerator(password_length)
            password = generator.generate()
            encrypted_password = self._encrypt_password(master_password, password)
            self._save_encrypted_password(service, encrypted_password)
            print(f"A random password for {service} has been successfully saved.")
        else:
            print("Invalid Master Password")

    def get_and_copy_password(self, master_password: str, service: str):
        """
        Get and copy the decrypted password.
        """
        if self._verify_master_password(master_password):
            encrypted_password = self._load_encrypted_password(service)
            if encrypted_password:
                decrypted_password = self._decrypt_password(
                    master_password, encrypted_password
                )
                pyperclip.copy(decrypted_password)
                print("Copied password to clipboard")
            else:
                print(f"password for {service} not found.")
        else:
            print("Invalid Master Password")

    def del_password(self, master_password: str, service: str):
        """
        Delete the service and its password.
        """
        master_pass_is_correct = self._verify_master_password(master_password)
        if master_pass_is_correct:
            data = self._load_data_from_file(self.passwords_path)
            if service in data:
                del data[service]
                with open(self.passwords_path, "wb") as file:
                    pickle.dump(data, file)
                print(f"{service} has been successfully deleted.")
            else:
                print(f"{service} not found.")
        else:
            print("Invalid Master Password")

    def print_data(self):
        """
        Print data to the console for viewing purposes.
        """
        if os.path.exists(self.user_info_path):
            user_data = self._load_data_from_file(self.user_info_path)
            for key, value in user_data.items():
                print(f"{key}: {value}")
        else:
            print("User info data not found.")

        if os.path.exists(self.passwords_path):
            password_data = self._load_data_from_file(self.passwords_path)
            for key, value in password_data.items():
                print(f"{key}: {value}")
        else:
            print("Password data not found.")

    def _verify_master_password(self, master_password: str) -> bool:
        """
        Verify the inputed master password matches the stored master password.
        """
        salt = self._load_salt_from_data()
        salted_master_password = PasswordEncrypter.add_salt(master_password, salt)
        hashed_password = PasswordEncrypter.hash_master_password(salted_master_password)
        return hashed_password == self._load_master_pass_from_data()
