from argparse import ArgumentParser
from password_vault import PasswordVault


class CLI:
    def __init__(self):
        self.vault = PasswordVault()
        self.parser = ArgumentParser()
        self.subparsers = self.parser.add_subparsers(title="command", dest="command")

        self.initialize_setup_cmd()
        self.initialize_set_cmd()
        self.initialize_get_cmd()
        self.initialize_del_cmd()
        self.initialize_gen_cmd()
        self.initialize_print_cmd()
        self.initialize_help_cmd()

    def initialize_setup_cmd(self):
        self.parser_setup_cmd = self.subparsers.add_parser("setup")
        self.parser_setup_cmd.set_defaults(func=self.vault.initialize_user)

    def initialize_set_cmd(self):
        self.parser_set_cmd = self.subparsers.add_parser("set")
        self.parser_set_cmd.add_argument(
            "service", type=str, help="The service you wish to pair the password with"
        )
        self.parser_set_cmd.set_defaults(func=self.vault.write_password)

    def initialize_get_cmd(self):
        self.parser_get_cmd = self.subparsers.add_parser("get")
        self.parser_get_cmd.add_argument(
            "service", type=str, help="The service whose password you want to get"
        )
        self.parser_get_cmd.set_defaults(func=self.vault.get_and_copy_password)

    def initialize_del_cmd(self):
        self.parser_del_cmd = self.subparsers.add_parser("del")
        self.parser_del_cmd.add_argument(
            "service", type=str, help="The service you wish to delete"
        )
        self.parser_del_cmd.set_defaults(func=self.vault.del_password)

    def initialize_gen_cmd(self):
        self.parser_gen_cmd = self.subparsers.add_parser("gen")
        self.parser_gen_cmd.add_argument(
            "service",
            type=str,
            help="The service you wish to pair the randomly generated password with",
        )
        self.parser_gen_cmd.set_defaults(func=self.vault.write_generated_password)

    def initialize_print_cmd(self):
         self.parser_print_cmd = self.subparsers.add_parser("print")
         self.parser_print_cmd.set_defaults(func=self.vault.print_data)
    
    def initialize_help_cmd(self):
        self.parser_help_cmd = self.subparsers.add_parser("help")
        self.parser_help_cmd.set_defaults(func=self.vault.print_help)

    def parse_arguments(self):
        args = self.parser.parse_args()
        if hasattr(args, "func"):
            if args.func == self.vault.initialize_user:
                args.func()

            elif args.func == self.vault.write_password:
                service = args.service
                args.func(service)

            elif args.func == self.vault.get_and_copy_password:
                service = args.service
                args.func(service)

            elif args.func == self.vault.del_password:
                service = args.service
                args.func(service)

            elif args.func == self.vault.write_generated_password:
                service = args.service
                args.func(service)
            
            elif args.func == self.vault.print_data:
                args.func()
            
            elif args.func == self.vault.print_help:
                args.func()
