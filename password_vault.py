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
        data = self._load_data_from_file(self.user_info_path)
        master_password = input("Enter a Master Password:\n")
        data["hashed_master_pass"] = self._hash_master_password(master_password)
        data["salt"] = self._generate_salt()
        with open(self.user_info_path, "wb") as file:
            pickle.dump(data, file)

    def write_password(self, master_password, service, password):
        """
        Write an encrypted password with its intended service to the file.

        Parameters:
        - master_password(string): The master password used to validate access and encrypt the password.
        - service(string): The service the encrypted password will be paired with.
        - password(string): The password we wish to encrypt and write to the json file.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._load_data_from_file(self.passwords_path)
            encrypted_password = self._encrypt_password(master_pass_key, password)
            hashed_service = self._hash_service(service)
            data[hashed_service] = encrypted_password
            with open(self.passwords_path, "wb") as file:
                pickle.dump(data, file)
        else:
            print("Invalid Master Password")
    
    def write_generated_password(self, master_password, service):
        """
        Write an encrypted randomly generated password with its intended service to the file.

        Parameters:
        - master_password(string): The master password used to validate access and encrypt the password.
        - service(string): The service the encrypted password will be paired with.
        """
        generated_password = self._generate_password()
        self.write_password(master_password, service, generated_password)

    def get_password(self, master_password, service):
        """
        Get and decrypt the desired password.

        Parameters:
        - master_password (string): The master password used to validate access and decrypt the password.
        - service (string): The service for which we want to retrieve and decrypt the password.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            salt = self._get_stored_salt()
            master_pass_key = self._get_master_pass_key(master_password, salt)
            data = self._load_data_from_file(self.passwords_path)
            hashed_service = self._hash_service(service)
            if hashed_service in data:
                encrypted_password = data[hashed_service]
                decryped_password = self._decrypt_password(
                    master_pass_key, encrypted_password
                )
                pyperclip.copy(decryped_password)
                print("Copied password to clipboard")
        else:
            print("Invalid Master Password")

    def del_password(self, master_password, service):
        """
        Delete the service and its password.

        Parameters:
        - master_password (string): The master password used to validate access.
        - service (string): The service whose password we want to delete.
        """
        master_pass_is_correct = self._validate_master_password(master_password)
        if master_pass_is_correct:
            data = self._load_data_from_file(self.passwords_path)
            hashed_service = self._hash_service(service)
            if hashed_service in data:
                del data[hashed_service]
                with open(self.passwords_path, "wb") as file:
                    pickle.dump(data, file)

    def _generate_password(self):
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
                    list(range(*special_ascii_dec_ranges[0])) +
                    list(range(*special_ascii_dec_ranges[1])) +
                    list(range(*special_ascii_dec_ranges[2])) +
                    list(range(*special_ascii_dec_ranges[3]))
                )
            
            password += chr(ascii_dec)
            char_counts[group] -= 1
            if char_counts[group] == 0:
                del char_groups[index]
                num_of_valid_groups -= 1
        
        return password

    def _validate_master_password(self, master_password):
        hashed_password_to_validate = self._hash_master_password(master_password)
        return hashed_password_to_validate == self._get_hashed_master_pass()

    def _hash_master_password(self, master_password):
        """
        Hashes the master password for validation purposes using the sha3_256 algorithm.

        Parameters:
        - master_password (string): A string representation of an unhashed master password.

        Returns:
        - bytes: The hashed master password as bytes.
        """
        encoded_password = master_password.encode()
        hashed_password = hashlib.sha3_256(encoded_password).digest()
        return hashed_password

    def _generate_salt(self):
        """
        Generate a random value (salt) used with the master password to generate a derived key
        for encryption/decryption.

        Returns:
        - bytes: The generated salt as bytes.
        """
        return os.urandom(16)

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

    def _hash_service(self, service):
        """
        Hashes the service name using the sha256 algorithm for security purposes.

        Parameters:
        - service (string): A string representation of an unhashed service name.

        Returns:
        - bytes: The hashed service name as bytes.
        """
        encoded_service = service.encode()
        hashed_service = hashlib.sha256(encoded_service).digest()
        return hashed_service

    def _encrypt_password(self, master_pass_key, password_to_encrypt):
        """
        Encrypts the password using the provided master password key.

        Parameters:
        - master_pass_key (bytes): The derived key generated from the master password.
        - password_to_encrypt (string): The password to be encrypted.

        Returns:
        - bytes: The encrypted password as bytes.
        """
        f = Fernet(master_pass_key)
        return f.encrypt(password_to_encrypt.encode())

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
        return f.decrypt(encrypted_password).decode()

    def _get_hashed_master_pass(self):
        """
        Retrieve the hashed master password from the user info.

        Returns:
        - bytes: The hashed master password.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["hashed_master_pass"]

    def _get_stored_salt(self):
        """
        Retrieve the stored salt from the user info.

        Returns:
        - bytes: The stored salt.
        """
        data = self._load_data_from_file(self.user_info_path)
        return data["salt"]

    def _load_data_from_file(self, path):
        """
        Retrieve and unpickle data from the specified file.

        Parameters:
        - path (string): The path to the file.

        Returns:
        - dict: The unpickled data.
        """
        if not os.path.exists(path):
            data = {}
        else:
            with open(path, "rb") as file:
                data = pickle.load(file)
        return data