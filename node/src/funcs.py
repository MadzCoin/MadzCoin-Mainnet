import getpass
import os
import secrets
import urllib

import rich
from eth_account import Account
from src.vars import *


def rgbPrint(string, color, end="\n"):
    rich.print("[" + color + "]" + str(string) + "[/" + color + "]", end=end)


def get_priv():
    if not os.path.exists(file_paths.privkey):
        rgbPrint("No private key detected, would you like to generate (1) or import one (2)?", "red")
        inputed = False
        while not inputed:
            type = input("Type 1 or 2: ")
            if type == "1":
                inputed = True
                priv = secrets.token_hex(32)
                public_key = Account.from_key(priv).address

                with open(file_paths.privkey, "w") as f:
                    f.write(priv)

            elif type == "2":
                inputed = True
                priv_inputed = False
                while not priv_inputed:
                    priv = getpass.getpass("Enter your private key: ")
                    priv.replace("0x", "")

                    try:
                        public_key = Account.from_key(priv).address
                        with open(file_paths.privkey, "w") as f:
                            f.write(priv)
                        priv_inputed = True

                    except:
                        priv_inputed = False
    else:
        with open(file_paths.privkey, "r") as f:
            priv = f.readlines()[0]
            public_key = Account.from_key(priv).address
        

    return {"public": public_key, "private": priv}
                

def read_yaml_config(print_host = True):
    if os.path.exists(file_paths.config):
        with open(file_paths.config, "r") as configs:
            global MOTD
            configyaml = yaml.safe_load(configs)

            nodeURL = str(configyaml["config"]["public_url"])

            if nodeURL.endswith("/"): nodeURL = nodeURL[:-1]

            try:
                MOTD = configyaml["config"]["MOTD"]
            except:
                pass

            try:
                privateHost = configyaml["config"]["private_host"]
            except:
                privateHost = "0.0.0.0"

            try:
                privatePort = configyaml["config"]["private_port"]
            except:
                port = ""

                for char in nodeURL.split(":")[1]:
                    if char.isdigit():
                        port += char
                    else:
                        break

                privatePort = int(port)

            try:
                ssl_keyfile = configyaml["config"]["ssl_keyfile"]
                ssl_certfile = configyaml["config"]["ssl_certfile"]
                ssl_ca_certs = configyaml["config"]["ssl_ca_certs"]
            except:
                ssl_keyfile = None
                ssl_certfile = None
                ssl_ca_certs = None
                          

            return ({"url": nodeURL}, {"host": privateHost, "port": privatePort}, {"ssl_keyfile": ssl_keyfile, "ssl_certfile": ssl_certfile, "ssl_ca_certs": ssl_ca_certs})
