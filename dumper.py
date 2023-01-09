import json

node = input("Enter Node you wish to add: ")

with open("node/peerlist.json","w") as f:
    json.dump({"Peers":[node]},f)