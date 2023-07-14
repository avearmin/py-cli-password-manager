from argparse import ArgumentParser
from password_vault import PasswordVault

class App:
    def __init__(self):
        self.vault = PasswordVault()
        self.parser = ArgumentParser()
        self.subparsers = self.parser.add_subparsers(title="command", dest="command")

        self.parser_setup_cmd = self.subparsers.add_parser('setup')
        self.parser_setup_cmd.set_defaults(func=self.vault.initialize_user)

        self.parser_set_cmd = self.subparsers.add_parser('set')
        self.parser_set_cmd.add_argument("master_password", type=str, help="The master password made in setup")
        self.parser_set_cmd.add_argument("service", type=str, help="The service you wish to pair the password with")
        self.parser_set_cmd.add_argument("password", type=str, help="The password you want to encrypt")
        self.parser_set_cmd.set_defaults(func=self.vault.write_password)

        self.parser_get_cmd = self.subparsers.add_parser('get')
        self.parser_get_cmd.add_argument("master_password", type=str, help="The master password made in setup")
        self.parser_get_cmd.add_argument("service", type=str, help="The service you wish to pair the password with")
        self.parser_get_cmd.set_defaults(func=self.vault.get_password)

    def parse_arguments(self):
        args = self.parser.parse_args()
        if hasattr(args, 'func'):
            if args.func == self.vault.initialize_user:
                args.func()

            elif args.func == self.vault.write_password:
                master_password = args.master_password
                service = args.service
                password = args.password
                args.func(master_password, service, password)

            elif args.func == self.vault.get_password:
                master_password = args.master_password
                service = args.service
                args.func(master_password, service)