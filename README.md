# py-cli-password-manager
A command-line tool built with Python for securely managing passwords.

## Dependencies

- cryptography
- pyperclip

You can install these dependencies using pip:
`pip install cryptography`
`pip install pyperclip`

You may encounter an error message that says: 'Pyperclip could not find a copy/paste mechanism for your system.' Please refer to the [Pyperclip documentation](https://pyperclip.readthedocs.io/en/latest/#not-implemented-error) for instructions on how to resolve this issue.

## Future Updates

Here are some planned features for the py-cli-password-manager project:

- **Password Creation:** Generate strong and unique passwords for each service or website to enhance security.
- **Password Strength Detector:** Evaluate the strength of each password and provide recommendations for updating weak passwords.

## Using The Password Manager

Currently the Password Manager supports 5 commands:

- `setup`: Set a master password, and generate salt. $ python main.py setup

- `set`: Store a password for a service. $ python main.py set master_password service password

- `get`: Retrieve a password for a service. $ python main.py get master_password service

- `del`: Delete a service/password pair. $ python main.py del master_password service

- `gen`: Generate a random password and store it. $ python main.py gen master_password service
