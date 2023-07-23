# py-cli-password-manager
A command-line tool built with Python for securely managing passwords.

## Setting up the Password Manager
This section will guide you through the setup process, including cloning the repository and setting up a permanent alias for convenient access.

### Dependencies

- cryptography
- pyperclip

You can install these dependencies using pip:
```bash
pip install cryptography
pip install pyperclip
```

You may encounter an error message that says: 'Pyperclip could not find a copy/paste mechanism for your system.' Please refer to the [Pyperclip documentation](https://pyperclip.readthedocs.io/en/latest/#not-implemented-error) for instructions on how to resolve this issue.

### Cloning the Repository
To get started, clone the py-cli-password-manager repository to your local machine:

```bash
git clone https://github.com/avearmin/py-cli-password-manager.git
cd py-cli-password-manager
```

### Creating a Permanent Alias
For convenience, you can create a permanent alias that allows you to access the Password Manager from any directory in your terminal.

Open your terminal and navigate to your home directory:
```bash
cd ~
```
Edit your shell profile file. Depending on the shell you're using (bash, zsh, etc.), the file could be one of the following:

- For bash, use ~/.bashrc or ~/.bash_profile
- For zsh, use ~/.zshrc

For example, if you're using bash:
```bash
nano ~/.bashrc
```

Add the following line at the end of the file to create an alias:
```bash
alias password-manager="python /path/to/py-cli-password-manager/main.py"
```
Replace /path/to/py-cli-password-manager with the actual path to the directory where you cloned the repository.
1. Save and close the file (for nano, press Ctrl + X, then Y, and finally Enter).
2. To apply the changes, either restart your terminal or run the following command:
```bash
source ~/.bashrc
```

## Features

The py-cli-password-manager project offers the following features:

- **Password Creation:** Generate strong and unique passwords for each service or website to enhance security.
- **Password Policy Enforcement:** Prevent the user from setting woefully unsecure passwords.
- **Password Encryption:** Encrypt passwords using the Fernet encryption scheme to protect sensitive information.
- **Password Storage:** Store encrypted passwords securely for each service or website.
- **Password Retrieval:** Decrypt and retrieve stored passwords when needed.
- **Clipboard Integration:** Copy passwords directly to the clipboard for convenient pasting into login forms.
- **Master Password:** Set a master password for accessing and managing stored passwords.

### Future Updates

Here are some planned features for the py-cli-password-manager project:

- **Password Strength Detector:** Evaluate the strength of each password and provide recommendations for updating weak passwords.

## Using The Password Manager

Currently the Password Manager supports 6 commands:

`setup`: Set a master password, and generate salt. 
```bash
$ your-alias setup
```

`set`: Store a password for a service. 
```bash
$ your-alias set master_password service
```

`get`: Retrieve a password for a service. 
```bash
$ your-alias get master_password service
```

`del`: Delete a service/password pair. 
```bash
$ your-alias del master_password service
```

`gen`: Generate a random password and store it. 
```bash
$ your-alias gen master_password service
```

`print`: Print data to the console. Note: This will not decrypt anything. 
```bash
$ your-alias print
```