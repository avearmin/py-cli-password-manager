from password_encryption import PasswordEncryption
from password_generator import PasswordGenerator
from password_validation import PasswordValidation
import os, pickle, pyperclip


class PasswordVault:
    """
    A class to securely manage and store encrypted passwords.
    """
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

        master_password = self._get_validated_password(min_pass_len)
        salt = PasswordEncryption.generate_salt()
        salted_master_password = PasswordEncryption.add_salt(master_password, salt)

        data = self._load_data_from_file(self.user_info_path)
        data["salt"] = salt
        data["master_pass"] = PasswordEncryption.hash_master_password(
            salted_master_password
        )
        with open(self.user_info_path, "wb") as file:
            pickle.dump(data, file)
        print("Master password, and salt have been successfully saved.")

    def write_password(self, master_password: str, service: str):
        """
        Write an encrypted password with its intended service to the file.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            min_pass_len = 8
            print(
                "Create a password with at least:\n"
                + f"{min_pass_len} characters, 1 uppercase, 1 lowercase "
                + "1 number, and 1 special character"
            )
            password = self._get_validated_password(min_pass_len)
            salt = self._get_stored_salt()
            master_pass_key = PasswordEncryption.get_master_pass_key(
                master_password, salt
            )
            data = self._load_data_from_file(self.passwords_path)
            encrypted_password = PasswordEncryption.encrypt_password(
                master_pass_key, password
            )
            data[service] = encrypted_password
            with open(self.passwords_path, "wb") as file:
                pickle.dump(data, file)
            print(f"{service} has been successfully saved.")
        else:
            print("Invalid Master Password")

    def write_generated_password(self, master_password: str, service: str):
        """
        Write an encrypted randomly generated password with its intended service to the file.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            password = PasswordGenerator.generate_password()
            salt = self._get_stored_salt()
            master_pass_key = PasswordEncryption.get_master_pass_key(
                master_password, salt
            )
            data = self._load_data_from_file(self.passwords_path)
            encrypted_password = PasswordEncryption.encrypt_password(
                master_pass_key, password
            )
            data[service] = encrypted_password
            with open(self.passwords_path, "wb") as file:
                pickle.dump(data, file)
            print(f"A random password for {service} has been successfully saved.")

        else:
            print("Invalid Master Password")

    def get_password(self, master_password: str, service: str):
        """
        Get and decrypt the desired password.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            salt = self._get_stored_salt()
            master_pass_key = PasswordEncryption.get_master_pass_key(
                master_password, salt
            )
            data = self._load_data_from_file(self.passwords_path)
            if service in data:
                encrypted_password = data[service]
                decryped_password = PasswordEncryption.decrypt_password(
                    master_pass_key, encrypted_password
                )
                pyperclip.copy(decryped_password)
                print("Copied password to clipboard")
            else:
                print(f"{service} not found.")
        else:
            print("Invalid Master Password")

    def del_password(self, master_password: str, service: str):
        """
        Delete the service and its password.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
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

    def _validate_master_password(self, master_password: str) -> bool:
        """
        Validate the inputed master password matches the stored master pass word.
        """
        salt = self._get_stored_salt()
        salted_master_password_to_validate = PasswordEncryption.add_salt(
            master_password, salt
        )
        hashed_password_to_validate = PasswordEncryption.hash_master_password(
            salted_master_password_to_validate
        )
        return hashed_password_to_validate == self._get_hashed_master_pass()

    def _get_validated_password(self, min_pass_len) -> str:
        """
        Continuously prompt the user until a validated password can be returned.
        """
        min_upper = 1
        min_lower = 1
        min_num = 1
        min_special = 1
        while True:
            password = input()
            validator = PasswordValidation(
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

    def _get_hashed_master_pass(self) -> bytes:
        """
        Retrieve the hashed master password from the user info.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["master_pass"]

    def _get_stored_salt(self) -> bytes:
        """
        Retrieve the stored salt.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["salt"]

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
