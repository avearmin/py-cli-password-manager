import os, json

class PasswordVault:
    def __init__(self):
        self.location = os.path.join(os.getcwd(), "vault", "passwords.json")

    def write_password(self, service, password):
        data = self._get_json_data()

        data[service] = password

        with open(self.location, "w") as json_file:
            json.dump(data, json_file, indent=4)

    def get_password(self, service):
        data = self._get_json_data()
        if service in data:
            print(f"{service}: {data[service]}")

    def _get_json_data(self):
        if not os.path.exists(self.location):
            data = {}
        else:
            with open(self.location, "r") as json_file:
                    data = json.load(json_file)
        return data

p = PasswordVault()

p.write_password("google", "123456")
p.get_password("google")
p.get_password("myspace")
