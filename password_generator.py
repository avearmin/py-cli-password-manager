import random


class PasswordGenerator:
    """
    A class for generating strong and secure random passwords.
    """

    def __init__(self, pass_len):
        """
        Initialize a PasswordGenerator object with a reference to desired password length.
        """
        self.password_length = pass_len

    def generate(self) -> str:
        """
        Generate a 20 character random password consisting of upper, lower, number,
        and special characters
        """
        char_counts = self._get_char_counts()
        password = self.build_password(char_counts)
        return password

    def _get_char_counts(self) -> dict:
        """
        Get a dict with random character counts.
        """
        char_counts = {"upper": 0, "lower": 0, "num": 0, "special": 0}
        char_groups = list(char_counts.keys())

        num_chars_left = self.password_length
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

        return char_counts

    def build_password(self, char_counts: dict) -> str:
        """
        Build a password with the amount of characters from char_counts.
        """
        char_groups = list(char_counts.keys())
        password = ""
        num_of_valid_groups = 4
        for i in range(self.password_length):
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
                    list(range(*special_ascii_dec_ranges[3])))

            password += chr(ascii_dec)
            char_counts[group] -= 1
            if char_counts[group] == 0:
                del char_groups[index]
                num_of_valid_groups -= 1

        return password
