from cryptography.fernet import Fernet
import os, hashlib, pickle, base64, pyperclip, random


class PasswordVault:
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
        salt = self._generate_salt()
        salted_master_password = self._add_salt(master_password, salt)

        data = self._load_data_from_file(self.user_info_path)
        data["salt"] = salt
        data["master_pass"] = self._hash_master_password(salted_master_password)
        with open(self.user_info_path, "wb") as file:
            pickle.dump(data, file)

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
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._load_data_from_file(self.passwords_path)
            encrypted_password = self._encrypt_password(master_pass_key, password)
            data[service] = encrypted_password
            with open(self.passwords_path, "wb") as file:
                pickle.dump(data, file)
        else:
            print("Invalid Master Password")

    def write_generated_password(self, master_password: str, service: str):
        """
        Write an encrypted randomly generated password with its intended service to the file.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            password = self._generate_password()
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._load_data_from_file(self.passwords_path)
            encrypted_password = self._encrypt_password(master_pass_key, password)
            data[service] = encrypted_password
            with open(self.passwords_path, "wb") as file:
                pickle.dump(data, file)
        else:
            print("Invalid Master Password")

    def get_password(self, master_password: str, service: str):
        """
        Get and decrypt the desired password.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._load_data_from_file(self.passwords_path)
            if service in data:
                encrypted_password = data[service]
                decryped_password = self._decrypt_password(
                    master_pass_key, encrypted_password
                )
                pyperclip.copy(decryped_password)
                print("Copied password to clipboard")
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

    def _generate_password(self) -> str:
        """
        Generate a 20 character random password consisting of upper, lower, number,
        and special characters
        """
        password_length = 20
        char_counts = {"upper": 0, "lower": 0, "num": 0, "special": 0}
        char_groups = list(char_counts.keys())

        num_chars_left = password_length
        num_of_valid_groups = 4
        while num_of_valid_groups != 1:
            index = random.randrange(0, num_of_valid_groups)
            num_to_divide_by = random.randrange(2, 5)
            random_count = num_chars_left // num_to_divide_by

            group = char_groups[index]
            char_counts[group] = random_count
            del char_groups[index]

            num_chars_left -= random_count
            num_of_valid_groups -= 1
        char_counts[char_groups[0]] = num_chars_left

        char_groups = list(char_counts.keys())
        password = ""
        num_of_valid_groups = 4
        for i in range(password_length):
            index = random.randrange(0, num_of_valid_groups)
            group = char_groups[index]

            if group == "upper":
                ascii_dec = random.randint(42, 91)
            if group == "lower":
                ascii_dec = random.randint(97, 123)
            if group == "num":
                ascii_dec = random.randint(48, 57)
            if group == "special":
                special_ascii_dec_ranges = ((33, 46), (58, 65), (91, 97), (123, 127))
                ascii_dec = random.choice(
                    list(range(*special_ascii_dec_ranges[0]))
                    + list(range(*special_ascii_dec_ranges[1]))
                    + list(range(*special_ascii_dec_ranges[2]))
                    + list(range(*special_ascii_dec_ranges[3]))
                )

            password += chr(ascii_dec)
            char_counts[group] -= 1
            if char_counts[group] == 0:
                del char_groups[index]
                num_of_valid_groups -= 1

        return password

    def _validate_master_password(self, master_password: str) -> bool:
        """
        Validate the inputed master password matches the stored master pass word.
        """
        salt = self._get_stored_salt()
        salted_master_password_to_validate = self._add_salt(master_password, salt)
        hashed_password_to_validate = self._hash_master_password(
            salted_master_password_to_validate
        )
        return hashed_password_to_validate == self._get_hashed_master_pass()

    def _hash_master_password(self, master_password: str) -> bytes:
        """
        Hashes the master password for validation purposes using the sha3_256 algorithm.
        """
        encoded_password = master_password.encode()
        hashed_password = hashlib.sha3_256(encoded_password).digest()
        return hashed_password

    def _generate_salt(self) -> bytes:
        """
        Generate a random value (salt) used with the master password to generate a derived key
        for encryption/decryption.
        """
        return os.urandom(16)
    
    def _add_salt(self, password: str, salt: bytes) -> str:
        """
        Add salt to the password.
        """
        salt_as_str = base64.b64encode(salt).decode()
        return password + salt_as_str

    def _get_master_pass_key(self, master_password: str, salt: bytes) -> bytes:
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

    def _encrypt_password(
        self, master_pass_key: bytes, password_to_encrypt: str
    ) -> bytes:
        """
        Encrypts the password using the provided master password key.
        """
        f = Fernet(master_pass_key)
        return f.encrypt(password_to_encrypt.encode())

    def _decrypt_password(
        self, master_pass_key: bytes, encrypted_password: bytes
    ) -> str:
        """
        Decrypts the encrypted password using the provided master password key.
        """
        f = Fernet(master_pass_key)
        return f.decrypt(encrypted_password).decode()

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

    def _get_validated_password(self, min_pass_len) -> str:
        """
        Continuously prompt the user until a validated password can be returned.
        """
        while True:
            password = input()
            is_password_valid = self._validate_password_criteria(password, min_pass_len)
            if is_password_valid:
                return password
            print(
                "Requirements not met. You need at least:\n"
                + f"{min_pass_len} characters, 1 uppercase, 1 lowercase, "
                + "1 number, and 1 special character"
            )

    def _validate_password_criteria(self, password: str, min_pass_len: int) -> bool:
        """
        Validate the password has at least: min_len or more characters,
        1 uppercase letter, 1 lowercase letter, 1 number, and
        1 special character.
        """
        return (
            len(password) >= min_pass_len
            and self._has_upper(password)
            and self._has_lower(password)
            and self._has_number(password)
            and self._has_special_character(password)
        )

    def _has_upper(self, password: str) -> bool:
        """
        Validate the password has at least 1 uppercase letter.
        """
        for char in password:
            if char.isalpha() and char.isupper():
                return True
        return False

    def _has_lower(self, password: str) -> bool:
        """
        Validate the password has at least 1 lowercase letter.
        """
        for char in password:
            if char.isalpha() and char.islower():
                return True
        return False

    def _has_number(self, password):
        """
        Validate the password has at least 1 number.
        """
        for char in password:
            if char.isnumeric():
                return True
        return False

    def _has_special_character(self, password: str) -> bool:
        """
        Validate the password has at least 1 special character.
        """
        special_chars = "~`!@#$%^&*()_-+={}[]\\|:;\"'<>,.?/"
        for char in password:
            if char in special_chars:
                return True
        return False
