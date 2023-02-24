"""
    Madzcoin Core V 0.13
    Copyright (c) 2023 The Madzcoin developers
    Distributed under the MIT software license, see the accompanying
    For copying see http://opensource.org/licenses/mit-license.php.
"""

#####################################################################
#                       Sections and what they mean:
#
#   -Vars and Imports:
#       Contains varibles and imported libs
#
#   -Config parsing:
#       Parses configs from "config.yaml"
#
#   -Subcores:
#       Provide useful functions to maintain node/network health
#
#   -Core:
#       Contains code **VITAL** to node operation(You can't go without this)
#
#   -Web:
#       Provides interface to(and from) the outside world
#
#   -Init:
#       Funcs for starting node
#
######################### Vars and imports ###########################

import dataclasses
import json
import threading
import time
import typing

import eth_account
import eth_account.messages
import eth_utils
import groestlcoin_hash
import requests
import rlp
import skein
from rlp.sedes import Binary, big_endian_int, binary
from src.funcs import get_priv, read_yaml_config, rgbPrint
from src.vars import *
from web3.auto import w3

######################### Core ###########################
class SignatureManager(object):
    def __init__(self):
        self.verified = 0
        self.signed = 0

    def signTransaction(self, private_key, transaction):
        message = eth_account.messages.encode_defunct(text=transaction["data"])
        transaction["hash"] = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        if signer == sender:
            transaction["sig"] = _signature
            self.signed += 1
        return transaction

    def verifyTransaction(self, transaction):
        message = eth_account.messages.encode_defunct(text=transaction["data"])
        _hash = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _hashInTransaction = transaction["hash"]
        signer = w3.eth.account.recover_message(message, signature=transaction["sig"])
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        result = ((signer == sender) and (_hash == _hashInTransaction))
        self.verified += int(result)
        return result

class ETHTransactionDecoder(object):
    class Transaction(rlp.Serializable):
        fields = [
            ("nonce", big_endian_int),
            ("gas_price", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("v", big_endian_int),
            ("r", big_endian_int),
            ("s", big_endian_int),
        ]


    @dataclasses.dataclass
    class DecodedTx:
        hash_tx: str
        from_: str
        to: typing.Optional[str]
        nonce: int
        gas: int
        gas_price: int
        value: int
        data: str
        chain_id: int
        r: str
        s: str
        v: int


    def decode_raw_tx(self, raw_tx: str):
        bytesTx = bytes.fromhex(raw_tx.replace("0x", ""))
        tx = rlp.decode(bytesTx, self.Transaction)
        hash_tx = w3.toHex(eth_utils.keccak(bytesTx))
        from_ = w3.eth.account.recover_transaction(raw_tx)
        to = w3.toChecksumAddress(tx.to) if tx.to else None
        data = w3.toHex(tx.data)
        r = hex(tx.r)
        s = hex(tx.s)
        chain_id = (tx.v - 35) // 2 if tx.v % 2 else (tx.v - 36) // 2
        return self.DecodedTx(hash_tx, from_, to, tx.nonce, tx.gas, tx.gas_price, tx.value, data, chain_id, r, s, tx.v)


class Message(object):
    def __init__(self, _from, _to, msg):
        self.sender = _from
        self.recipient = _to
        self.msg = msg


class Transaction(object):
    def __init__(self, tx):
        txData = json.loads(tx["data"])
        self.txtype = (txData.get("type") or 0)
        if self.txtype == 0:
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.recipient = w3.toChecksumAddress(txData.get("to"))
            self.value = max(float(txData.get("tokens")), 0)
        elif self.txtype == 1:
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.blockData = txData.get("blockData")
            self.recipient = "0x" + "0"*40
            self.value = 0.0
        elif self.txtype == 2:
            decoder = ETHTransactionDecoder()
            ethDecoded = decoder.decode_raw_tx(txData.get("rawTx"))
            self.sender = ethDecoded.from_
            self.recipient = ethDecoded.to
            self.value = max(float(ethDecoded.value/(10**18)), 0)
            self.nonce = ethDecoded.nonce
            self.ethData = ethDecoded.data
            self.ethTxid = ethDecoded.hash_tx
        elif self.txtype == 3:
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.recipient = w3.toChecksumAddress(txData.get("to"))
            self.value = max(float(txData.get("tokens")), 0)



        self.epoch = txData.get("epoch")
        self.bio = txData.get("bio")
        self.parent = txData.get("parent")
        self.message = txData.get("message")
        self.txid = tx.get("hash")



class GenesisBeacon(object):
    def __init__(self):
        self.timestamp = 1641738403
        self.miner = "0x" + "0"*40
        self.parent = "Initializing the chain".encode()
        self.difficulty = 1
        self.messages = "Hello world!".encode()
        self.nonce = 0
        self.miningTarget = "0x" + "f"*64
        self.proof = self.proofOfWork()
        self.transactions = []
        self.number = 0

    def beaconRoot(self):
        messagesHash = w3.soliditySha3(["bytes"], [self.messages])
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes","address"], [self.parent, self.timestamp, messagesHash, self.miner]) # parent PoW hash (bytes32), beacon's timestamp (uint256), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
        b = (b"".join([bytes.fromhex(bRoot.replace("0x", "")), int(self.nonce).to_bytes(32, 'big')]))
        return "0x" + groestlcoin_hash.getHash(b"".join([skein.skein256(b).digest(), self.nonce.to_bytes(32, "big")]), 64).hex()

    def difficultyMatched(self):
        return int(self.proofOfWork(), 16) < self.miningTarget

    def exportJson(self):
        return {"transactions": self.transactions, "messages": self.messages.hex(), "parent": self.parent.hex(), "timestamp": self.timestamp, "height": self.number, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget, "proof": self.proof}}


class Beacon(object):

    def __init__(self, data, difficulty):
        miningData = data["miningData"]
        self.miner = w3.toChecksumAddress(miningData["miner"])
        self.nonce = miningData["nonce"]
        self.difficulty = difficulty
        self.messages = bytes.fromhex(data["messages"])
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        self.timestamp = int(data["timestamp"])
        self.parent = data["parent"]
        self.transactions = []
        self.proof = self.proofOfWork()
        self.number = 0
        self.son = ""

    def beaconRoot(self):
        messagesHash = w3.soliditySha3(["bytes"], [self.messages])
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.parent, int(self.timestamp), messagesHash, self.miner]) # parent PoW hash (bytes32), beacon's timestamp (uint256), hash of messages (bytes32), beacon miner (address)
        return bRoot.hex()

    def proofOfWork(self):
        bRoot = self.beaconRoot()
        b = (b"".join([bytes.fromhex(bRoot.replace("0x", "")), int(self.nonce).to_bytes(32, 'big')]))
        return "0x" + groestlcoin_hash.getHash(b"".join([skein.skein256(b).digest(), self.nonce.to_bytes(32, "big")]), 64).hex()

    def difficultyMatched(self):

        return int(self.proofOfWork(), 16) < int(self.miningTarget, 16)

    def exportJson(self):
        return {"transactions": self.transactions, "messages": self.messages.hex(), "parent": self.parent, "son": self.son, "timestamp": self.timestamp, "height": self.number, "miningData": {"miner": self.miner, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.miningTarget, "proof": self.proof}}


class BeaconChain(object):
    def __init__(self):
        self.difficulty = 1
        self.miningTarget = "0x" + "f"*64
        self.blocks = [GenesisBeacon()]
        self.blocksByHash = {self.blocks[0].proof: self.blocks[0]}
        self.pendingMessages = []
        self.blockReward = BlockReward
        self.blockTime = IdealBlockTime
        self.cummulatedDifficulty = self.difficulty

    def checkBeaconMessages(self, beacon):
        _messages = beacon.messages.decode().split(",")
        for msg in _messages:
            if not msg in self.pendingMessages and msg != "null":
                return False
        return True

    def calcDifficulty(self, expectedDelay, timestamp1, timestamp2, currentDiff):
            return min(max((currentDiff * expectedDelay)/max((timestamp2 - timestamp1), 1), currentDiff * 0.9, 1), currentDiff*1.1)

    def isBeaconValid(self, beacon):
        _lastBeacon = self.getLastBeacon()
        if _lastBeacon.proof != beacon.parent:
            return (False, "UNMATCHED_BEACON_PARENT")
        if not self.checkBeaconMessages(beacon):
            return (False, "INVALID_MESSAGE")
        if not beacon.difficultyMatched():
            return (False, "UNMATCHED_DIFFICULTY")
        if int(beacon.timestamp) < _lastBeacon.timestamp or beacon.timestamp > time.time():
            return (False, "INVALID_TIMESTAMP")
        return (True, "GOOD")

    def isBlockValid(self, blockData, diff = None):
        if diff == None:
            diff = self.difficulty
        try:
            return self.isBeaconValid(Beacon(blockData, diff))
        except Exception as e:
            return (False, e)

    def getLastBeacon(self):
        return self.blocks[len(self.blocks) - 1]


    def addBeaconToChain(self, beacon):
        _messages = beacon.messages.decode()
        if _messages != "null":
            self.pendingMessages.remove(_messages)
        currentChainLength = len(self.blocks)
        self.getLastBeacon().son = beacon.proof
        _oldtimestamp = self.getLastBeacon().timestamp
        beacon.number = currentChainLength
        self.blocks.append(beacon)
        self.blocksByHash[beacon.proof] = beacon
        self.cummulatedDifficulty += self.difficulty
        self.difficulty = self.calcDifficulty(self.blockTime, _oldtimestamp, int(beacon.timestamp), self.difficulty)
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
        return True

    def submitBlock(self, block, showMessage):
        try:
            _beacon = Beacon(block, self.difficulty)
        except Exception as e:
            rgbPrint(e, "red")
            return False
        beaconValidity = self.isBeaconValid(_beacon)
        if beaconValidity[0]:
            self.addBeaconToChain(_beacon)
            if showMessage:
                rgbPrint(f"\n-----------\nNew Block mined!\nHeight: {_beacon.number}\nMiner: {_beacon.miner}\nReward: {self.blockReward} {CoinName} \n-----------\n", "green")
            return _beacon.miner
        return False

    def submitMessage(self, message):
        self.pendingMessages.append(message)

    def getBlockByHeightJSON(self, height):
        try:
            return self.blocks[height].exportJson()
        except:
            return None

    def getLastBlockJSON(self):
        return self.getLastBeacon().exportJson()


class State(object):
    def __init__(self):
        self.balances = {"0x"+"0"*36+"dEaD": 100, "0x"+"0"*40: 0}
        self.transactions = {"0x"+"0"*40: []}
        self.received = {"0x"+"0"*40: []}
        self.sent = {"0x"+"0"*40: []}
        self.mined = {"0x"+"0"*40: []}
        self.messages = {}
        self.accountBios = {"0x"+"0"*40: "Dead wallet", "0x"+"0"*36+"dEaD": "Dead wallet"}
        self.initTxID = "none"
        self.txChilds = {self.initTxID: []}
        self.txIndex = {}
        self.lastTxIndex = 0
        self.beaconChain = BeaconChain()
        self.holders = list((self.balances).keys())
        self.totalSupply = sum((self.balances).values())
        self.type2ToType0Hash = {}
        self.type0ToType2Hash = {}

    def getCurrentEpoch(self):
        return self.beaconChain.getLastBeacon().proof

    def getGenesisEpoch(self):
        return self.beaconChain.blocks[0].proof

    def ensureExistence(self, user):
        if not self.balances.get(user):
            self.balances[user] = 0
        if not self.transactions.get(user):
            self.transactions[user] = [self.initTxID]
        if not self.sent.get(user):
            self.sent[user] = [self.initTxID]
        if not self.received.get(user):
            self.received[user] = []
        if not self.received.get(user):
            self.mined[user] = []
        if not self.accountBios.get(user):
            self.accountBios[user] = ""

    def checkParent(self, tx):
        lastTx = self.getLastUserTx(tx.sender)
        if tx.txtype == 2:
            try:
                tx.parent = self.sent.get(tx.sender)[tx.nonce - 1]
            except:
                pass
            return (tx.nonce == len(self.sent.get(tx.sender)))
        else:
            return (tx.parent == lastTx)

    def checkBalance(self, tx):
        return tx.value > (self.balances.get(tx.sender) or 0)

    def updateHolders(self):
        _holders = []
        for key, value in self.balances.items():
            if value > 0:
                _holders.append(key)
        self.holders = _holders

    def estimateTransferSuccess(self, _tx):
        self.ensureExistence(_tx.sender)
        self.ensureExistence(_tx.recipient)
        if self.checkBalance(_tx):
            return (False, "Too low balance")
        if not self.checkParent(_tx):
            return (False, "Parent unmatched")

        return (True, "It'll succeed")

    def estimateMiningSuccess(self, tx, diff = None):
        self.ensureExistence(tx.sender)
        return self.beaconChain.isBlockValid(tx.blockData, diff=None)

    def isBeaconCorrect(self, tx):
        return (not tx.epoch) or (tx.epoch == self.getCurrentEpoch())

    def willTransactionSucceed(self, tx):
        _tx = Transaction(tx)
        underlyingOperationSuccess = (False, None)
        correctParent = self.checkParent(_tx)
        correctBeacon = self.isBeaconCorrect(_tx)
        if _tx.txtype == 0 or _tx.txtype == 2 or _tx.txtype == 3:
            underlyingOperationSuccess = self.estimateTransferSuccess(_tx)
        if _tx.txtype == 1:
            underlyingOperationSuccess = self.estimateMiningSuccess(_tx)

        return (underlyingOperationSuccess[0] and correctBeacon and correctParent)

    def applyParentStuff(self, tx):
        self.txChilds[tx.txid] = []
        if tx.txtype == 2:
            tx.parent = self.sent.get(tx.sender)[tx.nonce - 1]
            self.type2ToType0Hash[tx.ethTxid] = tx.txid
            self.type0ToType2Hash[tx.txid] = tx.ethTxid

        self.txChilds[tx.parent].append(tx.txid)
        self.txIndex[tx.txid] = self.lastTxIndex
        self.lastTxIndex += 1
        self.transactions[tx.sender].append(tx.txid)
        if tx.sender != tx.recipient:
            self.transactions[tx.recipient].append(tx.txid)
        if tx.txtype == 1:
            miner = tx.blockData.get("miningData").get("miner")
            self.ensureExistence(miner)
            self.mined[miner].append(tx.txid)
            self.transactions[miner].append(tx.txid)
        _txepoch = tx.epoch or self.getGenesisEpoch()
        if self.beaconChain.blocksByHash.get(_txepoch):
            self.beaconChain.blocksByHash[_txepoch].transactions.append(tx.txid)
        else:
            self.beaconChain.blocksByHash[self.getGenesisEpoch()].transactions.append(tx.txid)

        self.sent[tx.sender].append(tx.txid)
        self.received[tx.recipient].append(tx.txid)

    def executeTransfer(self, tx, showMessage):
        willSucceed = self.estimateTransferSuccess(tx)
        if not willSucceed[0]:
            return willSucceed
        self.applyParentStuff(tx)


        self.balances[tx.sender] -= tx.value
        self.balances[tx.recipient] += tx.value

        if showMessage:
            rgbPrint(f"\n-----------\nNew Transfer executed!\nAmount transferred: {tx.value}\nFrom: {tx.sender}\nTo: {tx.recipient} \n-----------\n", "yellow")
        return (True, "Transfer succeeded")

    def mineBlock(self, tx, showMessage):
        try:
            self.ensureExistence(tx.sender)
            feedback = self.beaconChain.submitBlock(tx.blockData, showMessage);
            self.applyParentStuff(tx)
            if feedback:
                self.balances[feedback] += self.beaconChain.blockReward
                self.totalSupply += self.beaconChain.blockReward
                return True
            return False
        except:
            raise
            return False

    def playTransaction(self, tx, showMessage):
        _tx = Transaction(tx)
        feedback = False
        if _tx.txtype == 1:
            feedback = self.mineBlock(_tx, showMessage)
        else:
            feedback = self.executeTransfer(_tx, not _tx.txtype == 3 and showMessage)


        if _tx.bio:
            self.accountBios[_tx.sender] = _tx.bio.replace("%20", " ")
        self.updateHolders()
        return feedback

    def getLastUserTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if len(self.transactions[user]) > 0:
            return self.transactions[user][len(self.transactions[user])-1]
        else:
            return self.initTxID

    def getLastSentTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if len(self.sent[user]) > 0:
            return self.sent[user][len(self.sent[user])-1]
        else:
            return self.initTxID

    def getLastReceivedTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.received[user]))>0:
            return self.received[user][len(self.received[user])-1]
        else:
            return None


class Peer(object):
    def __init__(self, url):
        self.url = url


class peer_discovery(object):
    def __init__(self, public_node):
        self.public_node = public_node

    def peerupdate(self):
        data = json.load(open(file_paths.peerlist, "r"))
        for peer in data["Peers"]:
            if peer == self.public_node["url"]:
                data["Peers"].remove(peer)
                json.dump(data, open(file_paths.peerlist, "w"))
        return data["Peers"]

    def updatepeerfile(self, peerremove):
        data = json.load(open(file_paths.peerlist, "r"))
        data["Peers"].remove(peerremove)
        json.dump(data, open(file_paths.peerlist, "w"))

    def addtopeerlist(self, peer):
        data = json.load(open(file_paths.peerlist, "r"))
        if peer not in data["Peers"]:
            data["Peers"].append(peer)
        json.dump(data, open(file_paths.peerlist, "w"))


class Node(object):
    def __init__(self):
        self.transactions = {}
        self.txsOrder = []
        self.mempool = []
        self.sigmanager = SignatureManager()
        self.state = State()
        self.bestBlockChecked = 0
        self.goodPeers = []
        self.public_node = read_yaml_config(print_host = False)[0]
        self.peer = peer_discovery(self.public_node).peerupdate()
        self.peerlist = peer_discovery(self.public_node).peerupdate()
        self.checkGuys()
        self.initNode()

    def canBePlayed(self, tx):
        sigVerified = False
        playableByState = False

        if dict(json.loads(tx.get("data"))).get("type") != 2:
            sigVerified = self.sigmanager.verifyTransaction(tx)

        else:
            sigVerified = True

        playableByState = self.state.willTransactionSucceed(tx)

        return (sigVerified and playableByState, sigVerified, playableByState)

    def addTxToMempool(self, tx):
        if self.canBePlayed(tx)[1]:
            self.mempool.append(tx)

    def send_registration_tx(self):
        global REG_TXID, PUB_KEY
        addr = self.keys["public"]
        priv = self.keys["private"]

        txs = self.state.transactions.get(addr) or ['none']
        tx = {'data': json.dumps({"from": addr, "to": addr, "tokens": 0, "parent": txs[len(txs)-1], "epoch": self.state.beaconChain.getLastBlockJSON()["miningData"]["proof"], "type": 3, "node": {"timestamp": time.time(), "addr": self.public_node["url"]}})}

        message = eth_account.messages.encode_defunct(text=tx["data"])
        tx["hash"] = w3.soliditySha3(["string"], [tx["data"]]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=priv).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(json.loads(tx["data"])["from"])
        if (signer == sender):
            tx["sig"] = _signature

        self.checkTxs([tx], False)
        rgbPrint(f"Sent registration TX, TXID: {tx['hash']}", "green")
        REG_TXID = tx['hash']
        PUB_KEY = addr
        return tx['hash']

    def initNode(self):
        self.public_node = read_yaml_config(print_host = False)[0]
        self.peer_discovery = peer_discovery(self.public_node)
        self.peerlist = self.peer_discovery.peerupdate()
        self.keys = get_priv()

        try:
            self.loadDB()
        except:
            rgbPrint("Error loading DB, nulling stats to zero :/", "red")

        were_txs_upgraded = self.upgradeTxs()
        were_txs_played = False

        play_txs_start = time.perf_counter()
        for txHash in self.txsOrder:
            tx = self.transactions[txHash]
            if self.canBePlayed(tx)[0]:
                self.state.playTransaction(tx, False)
                were_txs_played = True

        rgbPrint(f"Time taken to play TXs: {round(time.perf_counter() - play_txs_start, 2)}s", "yellow")
        rgbPrint(f"\nYour public key: {self.keys['public']}", "green")

        if were_txs_played or were_txs_upgraded:
            self.saveDB()


        self.syncByBlock()
        self.send_registration_tx()
        self.saveDB()

    def checkTxs(self, txs, print = True):
        _counter = 0
        for tx in txs:
            playable = self.canBePlayed(tx)
            if not self.transactions.get(tx["hash"]) and playable[0]:
                self.transactions[tx["hash"]] = tx
                self.txsOrder.append(tx["hash"])
                self.state.playTransaction(tx, True)
                self.propagateTransactions([tx])
                _counter += 1
                if print:
                    rgbPrint(f"Successfully saved transaction: {tx['hash']} \n", "honeydew2")
        if _counter > 0:
            if print:
                rgbPrint(f"Successfully saved {_counter} transactions!", "orchid")
        self.saveDB()

    def saveDB(self):
        toSave = json.dumps({"transactions": self.transactions, "txsOrder": self.txsOrder})
        file = open(file_paths.database, "w")
        file.write(toSave)
        file.close()

    def loadDB(self):
        start = time.perf_counter()
        file = open(file_paths.database, "r")
        db = json.load(file)
        self.transactions = db["transactions"]
        self.txsOrder = db["txsOrder"]
        file.close()
        rgbPrint(f"Time taken to load DB: {round(time.perf_counter() - start, 2)}s", "yellow")

    def upgradeTxs(self):
        start = time.perf_counter()
        changed_anything = False
        for txid in self.txsOrder:
            if type(self.transactions[txid]["data"]) == dict:
                self.transactions[txid]["data"] = json.dumps(self.transactions[txid]["data"]).replace(" ", "")
                changed_anything = True

        rgbPrint(f"Time taken to upgrade TXs: {round(time.perf_counter() - start, 2)}s", "yellow")
        return changed_anything

# REQUESTING DATA FROM PEERS
    """
    def checkPeers(self):
        for peer in self.goodPeers:
            peerver = requests.get(f"{peer}/NodeVer").json()["result"]
            if peerver == VER:
                rgbPrint(f"{peer} is the same version as you (V{VER})", "green")
    """
    def newpeersend(self): #Add your node, to the peers
        self.checkGuys()
        for peer in self.goodPeers:
            if peer != self.public_node["url"]:
                try:
                    requests.get(f"{peer}/net/NewPeer/{self.public_node['host']}/{self.public_node['port']}/{self.public_node['proto']}")
                except:
                    pass

    def askForMorePeers(self):
        public_node = read_yaml_config(print_host=False)[0]
        for peer in self.peerlist:
            try:
                obtainedPeers = requests.get(f"{peer}/net/getOnlinePeers")
                peerver = requests.get(f"{peer}/NodeVer").json()["result"]

                if peerver == VER:

                    if obtainedPeers.status_code == 200:
                        obtainedPeers = obtainedPeers.json()
                        obpeers = obtainedPeers["result"]
                        obpeersn = str(obpeers)[1:-1]
                        obpeersjson = str(obpeersn)[1:-1]

                        if obpeersjson != "" and obpeersjson != public_node["url"] and obpeersjson not in self.peerlist:
                            rgbPrint("Pinging new node: " + obpeersjson, "yellow")
                        else:
                            pass

                        if not(obpeersjson in self.peerlist) and obpeersjson != public_node["url"] and obpeersjson != "": #If node is not in the peerlist, and is not trying to add itself
                            self.peerlist.append(obpeersjson)
                            peer_discovery("").addtopeerlist(obpeersjson)
                else:
                    rgbPrint(f"{peer} is on a different version to your node!", "red")
                    try:
                        peer_discovery("").updatepeerfile(peer)
                    except:
                        pass

            except requests.exceptions.RequestException:
                pass

    def peercheck(self):
        for peer in self.goodPeers:
            try:
                requests.get(f"{peer}/ping")
            except:
                rgbPrint(f"{peer} seems offline! removing now!", "red")
                peer_discovery("").updatepeerfile(peer)
                self.peerlist.remove(peer)
                self.goodPeers.remove(peer)

    def checkGuys(self):
        self.goodPeers = []
        for peer in self.peerlist:
            try:
                if requests.get(f"{peer}/ping").json()["success"]:
                    peerver = requests.get(f"{peer}/NodeVer").json()["result"]
                    if peerver == VER and peer != self.public_node["url"]:
                        #rgbPrint(f"{peer} is the same version as you (V{VER})", "green")
                        self.goodPeers.append(peer)
                    else:
                        rgbPrint(f"{peer} is on a different version to you! (Your version {VER}\n {peer} version {peerver})")
                        self.peerlist.remove(peer)
                        peer_discovery("").updatepeerfile(peer)
                        pass
            except:
                pass

        self.askForMorePeers()
        self.goodPeers = []
        for peer in self.peerlist:
            try:
                if requests.get(f"{peer}/ping").json()["success"] and peer not in self.goodPeers:
                    self.goodPeers.append(peer)
            except:
                pass

    def addwebpeer(self, url, port, proto):
        public_node = read_yaml_config(print_host=False)[0]
        try:
            if proto == "http":
                url = "http://" + url + ":" + port
            if proto == "https":
                url = "https://" + url + ":" + port
            if url != public_node["url"]:
                try:
                    nodeping = requests.get(f"{url}/ping").json()
                    NodeVer = requests.get(f"{url}/NodeVer").json()
                except:
                    #rgbPrint("Could not Verify/ping new node", "red")
                    time.sleep(3)

                if nodeping["success"] == True and url != public_node["url"]:
                    if NodeVer["result"] == VER:
                        verack = "OK"
                        verifystatus = "OK"

                        if proto == "http" or proto == "https":
                            data = json.load(open(file_paths.peerlist))

                            if url not in self.peerlist:
                                data["Peers"].append(url)
                                rgbPrint("Adding new node: " + url+ f" ({NodeVer['result']})", "yellow")
                                self.peerlist.append(url)
                                self.checkGuys()
                            else:
                                rgbPrint("Node already added!")

                            json.dump(data, open(file_paths.peerlist, "w"))
                            requests.get(f"{url}/net/NewPeerok/{verack}")
                            requests.get(f"{url}/net/NewPeerstatus/{verifystatus}")

                    else:
                        rgbPrint("**Node's Version is not compatible with yours!**","red")
                        verack = "NO"
                        requests.get(f"{url}/net/NewPeerok/{verack}")

                        rgbPrint("Node version incompatible")
                else:
                    rgbPrint(f"A node requested you to add their ip to {file_paths.peerlist} but it seems down? (sussy)", "red")
        except:
            pass

    def pullSetOfTxs(self, txids):
        txs = []
        for txid in txids:
            localTx = self.transactions.get(txid)
            if not localTx:
                for peer in self.goodPeers:
                    try:
                        tx = requests.get(f"{peer}/get/transactions/{txid}").json()["result"][0]
                        txs.append(tx)
                        break
                    except:
                        raise
            else:
                txs.append(localTx)
        return txs

    def pullChildsOfATx(self, txid):
        vwjnvfeuuqubb = self.state.txChilds.get(txid) or []
        children = vwjnvfeuuqubb.copy()
        for peer in self.goodPeers:
            try:
                _childs = requests.get(f"{peer}/accounts/txChilds/{txid}").json()["result"]
                for child in _childs:
                    if not (child in children):
                        pulledTxData = json.loads(self.pullSetOfTxs([child])[0]["data"])
                        if pulledTxData["parent"] == txid or pulledTxData["type"] == 2:
                            children.append(child)
                break
            except:
                pass
        return children

    def pullTxsByBlockNumber(self, blockNumber):
        txs = []
        try:
            txs = self.state.beaconChain.blocks.get(blockNumber).transactions.copy()
        except:
            txs = []
        for peer in self.goodPeers:
            try:
                _txs = requests.get(f"{peer}/chain/block/{blockNumber}").json()["result"]["transactions"]
                for _tx in _txs:
                    if not (_tx in txs):
                        txs.append(_tx)
                break
            except:
                pass
        return txs

    def execTxAndRetryWithChilds(self, txid):
        tx = self.pullSetOfTxs([txid])
        self.checkTxs(tx)
        _childs = self.pullChildsOfATx(txid)
        for txid in _childs:
            self.execTxAndRetryWithChilds(txid)

    def syncDB(self):
        self.checkGuys()
        toCheck = self.pullChildsOfATx("none")
        for txid in toCheck:
            _childs = self.execTxAndRetryWithChilds(txid)

    def getChainLength(self):
        self.checkGuys()
        length = 0
        for peer in self.goodPeers:
            try:
                length = max(requests.get(f"{peer}/chain/length").json()["result"], length)
            except:
                pass
        return length

    def syncByBlock(self):
        self.checkTxs(self.pullSetOfTxs(self.pullTxsByBlockNumber(0)))
        for blockNumber in range(self.bestBlockChecked, self.getChainLength()):
            _toCheck_ = self.pullSetOfTxs(self.pullTxsByBlockNumber(blockNumber))
            rgbPrint(f"Synced block: {blockNumber} (Syncing with blockchain!)", "purple4")
            self.checkTxs(_toCheck_)
            self.bestBlockChecked = blockNumber


    def propagateTransactions(self, txs):
        toPush = []
        for tx in txs:
            txString = json.dumps(tx).replace(" ", "")
            txHex = txString.encode().hex()
            toPush.append(txHex)
        toPush = ",".join(toPush)
        for node in self.goodPeers:
            try:
                requests.get(f"{node}/send/rawtransaction/?tx={toPush}")
            except:
                pass

    def networkBackgroundRoutine(self):
        while True:
            self.checkGuys()
            self.syncByBlock()
            self.newpeersend()
            self.peercheck()
            time.sleep(15)

    def txReceipt(self, txid):
        _txid = txid
        if self.state.type2ToType0Hash.get(txid):
            _txid = self.state.type2ToType0Hash.get(txid)

        if self.transactions.get(_txid) == None:
            return {"transactionHash": _txid,"transactionIndex": None,"blockNumber": None, "blockHash": None, "cumulativeGasUsed": '0x5208', "gasUsed": '0x5208',"contractAddress": None,"logs": [], "logsBloom": "0x"+"0"*512,"status": '0x0'}
        else:
            _tx_ = Transaction(self.transactions.get(_txid))
            _blockHash = _tx_.epoch or self.state.getGenesisEpoch()
            _beacon_ = self.state.beaconChain.blocksByHash.get(_blockHash)
            return {"transactionHash": _txid,"transactionIndex":  '0x1',"blockNumber": _beacon_.number, "blockHash": _blockHash, "cumulativeGasUsed": '0x5208', "gasUsed": '0x5208',"contractAddress": None,"logs": [], "logsBloom": "0x"+"0"*512,"status": '0x1'}

    def integrateETHTransaction(self, ethTx):
        data = json.dumps({"rawTx": ethTx, "epoch": self.state.getCurrentEpoch(), "type": 2})
        _txid_ = w3.soliditySha3(["string"], [data]).hex()
        self.checkTxs([{"data": data, "hash": _txid_}])
        return _txid_


class TxBuilder(object):
    def __init__(self, node):
        self.signer = SignatureManager()
        self.node = node

    def buildTransaction(self, priv_key, _from, _to, tokens):
        from_ = w3.toChecksumAddress(_from)
        to_ = w3.toChecksumAddress(_to)
        data = json.dumps({"from": from_, "to": to_, "tokens": tokens, "parent": self.state.getLastSentTx(_from), "type": 0})
        tx = {"data": data}
        tx = self.signer.signTransaction(priv_key, tx)
        playable = self.node.canBePlayed(tx)
        self.checkTxs([tx])
        return (tx, playable)

node = Node()
maker = TxBuilder(node)
thread = threading.Thread(target=node.networkBackgroundRoutine)
thread.start()
