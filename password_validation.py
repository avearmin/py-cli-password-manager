class PasswordValidation:
    """
    A class for validating passwords against specified criteria.
    """
    def __init__(
        self,
        min_len: int,
        min_upper: int,
        min_lower: int,
        min_num: int,
        min_special: int,
    ):
        """
        Initialize a PasswordValidation object with minimum password complexity requirements.
        """
        self.min_len = min_len
        self.min_upper = min_upper
        self.min_lower = min_lower
        self.min_num = min_num
        self.min_special = min_special

    def validate(self, password) -> bool:
        """
        Validate the password meets the minimum requirements.
        """
        return (
            len(password) >= self.min_len
            and self._has_upper(password)
            and self._has_lower(password)
            and self._has_number(password)
            and self._has_special_character(password)
        )

    def _has_upper(self, password: str) -> bool:
        """
        Validate the password meets the minimum count of uppercase letters.
        """
        count = 0
        for char in password:
            if char.isalpha() and char.isupper():
                count += 1
        return count >= self.min_upper

    def _has_lower(self, password) -> bool:
        """
        Validate the password meets the minimum count of lowercase letters.
        """
        count = 0
        for char in password:
            if char.isalpha() and char.islower():
                count += 1
        return count >= self.min_lower

    def _has_number(self, password):
        """
        Validate the password meets the minimum count of numbers.
        """
        count = 0
        for char in password:
            if char.isnumeric():
                count += 1
        return count >= self.min_num

    def _has_special_character(self, password) -> bool:
        """
        Validate the password meets the minimum count of special characters.
        """
        count = 0
        special_chars = "~`!@#$%^&*()_-+={}[]\\|:;\"'<>,.?/"
        for char in password:
            if char in special_chars:
                count += 1
        return count >= self.min_special
