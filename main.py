######################################

# Thanks to Sirious coin for the source code 
# checkout their project at https://github.com/Sirious-io

######################################

from web3.auto import w3
from rlp.sedes import Binary, big_endian_int, binary
from fastapi.middleware.cors import CORSMiddleware
import requests, time, json, threading, uvicorn, fastapi, pydantic, rich, rlp, eth_utils, dataclasses, typing, eth_account.messages, groestlcoin_hash, skein


Web3ChainID = 5151
CoinName = "MadzCoin"
IdealBlockTime = 300
BlockReward = 10.5

nodeHost = "10.9.115.178"
#nodeHost ="0.0.0.0"
nodePort = 5005


transactions = {}

config = {"dataBaseFile": "database.json", "peers": [""], "InitTxID": "none"}


def rgbPrint(string, color, end="\n"):
    rich.print("[" + color + "]" + str(string) + "[/" + color + "]", end=end)


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
        if (signer == sender):
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
        if (self.txtype == 0):
            self.sender = w3.toChecksumAddress(txData.get("from"))
            self.recipient = w3.toChecksumAddress(txData.get("to"))
            self.value = max(float(txData.get("tokens")), 0)
        if (self.txtype == 1):
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
        b = (b"".join([bytes.fromhex(bRoot.replace("0x", "")),int(self.nonce).to_bytes(32, 'big')]))
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
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty),0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
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
        b = (b"".join([bytes.fromhex(bRoot.replace("0x", "")),int(self.nonce).to_bytes(32, 'big')]))
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
            if (not msg in self.pendingMessages) and (msg != "null"):
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
        if ((int(beacon.timestamp) < _lastBeacon.timestamp) or (beacon.timestamp > time.time())):
            return (False, "INVALID_TIMESTAMP")
        return (True, "GOOD")


    def isBlockValid(self, blockData):
        try:
            return self.isBeaconValid(Beacon(blockData, self.difficulty))
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
        self.miningTarget = hex(int(min(int((2**256-1)/self.difficulty),0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)))
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
                rgbPrint(f"\n-----------\nBlock mined!\nHeight : {_beacon.number}\nMiner : {_beacon.miner}\nReward : {self.blockReward} {CoinName} \n-----------\n", "green")
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
    def __init__(self, initTxID):
        self.balances = {"0x"+"0"*36+"dEaD": 100, "0x"+"0"*40: 0}
        self.transactions = {"0x"+"0"*40: []}
        self.received = {"0x"+"0"*40: []}
        self.sent = {"0x"+"0"*40: []}
        self.mined = {"0x"+"0"*40: []}
        self.messages = {}
        self.accountBios = {"0x"+"0"*40: "Dead wallet", "0x"+"0"*36+"dEaD": "Dead wallet"}
        self.initTxID = initTxID
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

    def estimateMiningSuccess(self, tx):
        self.ensureExistence(tx.sender)
        return self.beaconChain.isBlockValid(tx.blockData)

    def isBeaconCorrect(self, tx):
        return (not tx.epoch) or (tx.epoch == self.getCurrentEpoch())

    def willTransactionSucceed(self, tx):
        _tx = Transaction(tx)
        underlyingOperationSuccess = (False, None)
        correctParent = self.checkParent(_tx)
        correctBeacon = self.isBeaconCorrect(_tx)
        if _tx.txtype == 0 or _tx.txtype == 2:
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
        if (tx.sender != tx.recipient):
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

        if (showMessage):
            rgbPrint(f"\n-----------\nTransfer executed!\nAmount transferred : {tx.value}\nFrom: {tx.sender}\nTo: {tx.recipient} \n-----------\n", "yellow")
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
        if _tx.txtype == 0:
            feedback = self.executeTransfer(_tx, showMessage)
        if _tx.txtype == 1:
            feedback = self.mineBlock(_tx, showMessage)
        if _tx.txtype == 2:
            feedback = self.executeTransfer(_tx, showMessage)


        if (_tx.bio):
            self.accountBios[_tx.sender] = _tx.bio.replace("%20", " ")
        self.updateHolders()
        return feedback

    def getLastUserTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.transactions[user]))>0:
            return self.transactions[user][len(self.transactions[user])-1]
        else:
            return self.initTxID

    def getLastSentTx(self, _user):
        user = w3.toChecksumAddress(_user)
        self.ensureExistence(user)
        if (len(self.sent[user]))>0:
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

class Node(object):
    def __init__(self, config):
        self.transactions = {}
        self.txsOrder = []
        self.mempool = []
        self.sigmanager = SignatureManager()
        self.state = State(config["InitTxID"])
        self.config = config
        self.peers = config["peers"]
        self.bestBlockChecked = 0
        self.goodPeers = []
        self.checkGuys()
        self.initNode()


    def canBePlayed(self, tx):
        sigVerified = False
        playableByState = False
        if json.loads(tx.get("data")).get("type") != 2:
            sigVerified = self.sigmanager.verifyTransaction(tx)
        else:
            sigVerified = True
        playableByState = self.state.willTransactionSucceed(tx)
        return (sigVerified and playableByState, sigVerified, playableByState)


    def addTxToMempool(self, tx):
        if (self.canBePlayed(tx)[1]):
            self.mempool.append(tx)


    def initNode(self):
        try:
            self.loadDB()
            rgbPrint("Successfully loaded node DB!", "green")
        except:
            rgbPrint("Error loading DB, starting from zero :/", "red")
        self.upgradeTxs()
        for txHash in self.txsOrder:
            tx = self.transactions[txHash]
            if self.canBePlayed(tx)[0]:
                self.state.playTransaction(tx, False)
        self.saveDB()
        self.syncByBlock()
        self.saveDB()

    def checkTxs(self, txs):
        _counter = 0
        for tx in txs:
            playable = self.canBePlayed(tx)
            if (not self.transactions.get(tx["hash"]) and playable[0]):
                self.transactions[tx["hash"]] = tx
                self.txsOrder.append(tx["hash"])
                self.state.playTransaction(tx, True)
                self.propagateTransactions([tx])
                _counter += 1
                rgbPrint(f"Successfully saved transaction: {tx['hash']} \n", "honeydew2")
        if _counter > 0:
            rgbPrint(f"Successfully saved {_counter} transactions!", "orchid")
        self.saveDB()

    def saveDB(self):
        toSave = json.dumps({"transactions": self.transactions, "txsOrder": self.txsOrder})
        file = open(self.config["dataBaseFile"], "w")
        file.write(toSave)
        file.close()

    def loadDB(self):
        file = open(self.config["dataBaseFile"], "r")
        file.seek(0)
        db = json.load(file)
        self.transactions = db["transactions"]
        self.txsOrder = db["txsOrder"]
        file.close()

    def upgradeTxs(self):
        for txid in self.txsOrder:
            if type(self.transactions[txid]["data"]) == dict:
                self.transactions[txid]["data"] = json.dumps(self.transactions[txid]["data"]).replace(" ", "")




    # REQUESTING DATA FROM PEERS
    def askForMorePeers(self):
        for peer in self.goodPeers:
            try:
                obtainedPeers = requests.get(f"{peer}/net/getOnlinePeers")
                for _peer in obtainedPeers:
                    if not (peer in self.peers):
                        self.peers.append(peer)
            except:
                pass

    def checkGuys(self):
        self.goodPeers = []
        for peer in self.peers:
            try:
                if (requests.get(f"{peer}/ping").json()["success"]):
                    self.goodPeers.append(peer)
            except:
                pass
        self.askForMorePeers()
        self.goodPeers = []
        for peer in self.peers:
            try:
                if (requests.get(f"{peer}/ping").json()["success"]):
                    self.goodPeers.append(peer)
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
                        if (pulledTxData["parent"] == txid) or (pulledTxData["type"] == 2):
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
        toCheck = self.pullChildsOfATx(self.config["InitTxID"])
        for txid in toCheck:
            _childs = self.execTxAndRetryWithChilds(txid)

    def getChainLength(self):
        self.checkGuys()
        length = 0
        for peer in self.goodPeers:
            length = max(requests.get(f"{peer}/chain/length").json()["result"], length)
        return length

    def syncByBlock(self):
        self.checkTxs(self.pullSetOfTxs(self.pullTxsByBlockNumber(0)))
        for blockNumber in range(self.bestBlockChecked,self.getChainLength()):
            _toCheck_ = self.pullSetOfTxs(self.pullTxsByBlockNumber(blockNumber))
            rgbPrint(f"Synced block: {blockNumber}", "purple4")
            self.checkTxs(_toCheck_)
            self.bestBlockChecked = blockNumber


    def propagateTransactions(self,txs):
        toPush = []
        for tx in txs:
            txString = json.dumps(tx).replace(" ", "")
            txHex = txString.encode().hex()
            toPush.append(txHex)
        toPush = ",".join(toPush)
        for node in self.goodPeers:
            requests.get(f"{node}/send/rawtransaction/?tx={toPush}")

    def networkBackgroundRoutine(self):
        while True:
            self.checkGuys()
            self.syncByBlock()
            time.sleep(60)


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

if __name__ == "__main__":
    node = Node(config)
    rgbPrint(node.config, "royal_blue1")
    maker = TxBuilder(node)
    thread = threading.Thread(target=node.networkBackgroundRoutine)
    thread.start()


def jsonify(result, success = True):

    return {"result": result, "success": success}


# HTTP INBOUND PARAMS
app = fastapi.FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def basicInfoHttp():
    return  f"{CoinName} cryptocurrency MainNet running on port http: 5005 / https: 5006, local http: {nodePort} (Have fun using the network!)"

@app.get("/ping")
def getping():
    return {"result": "Pong!", "success": True}

@app.get("/stats")
def getStats():
    _stats_ = {"coin": {"transactions": len(node.txsOrder), "supply": node.state.totalSupply, "holders": len(node.state.holders)}, "chain" : {"length": len(node.state.beaconChain.blocks), "difficulty" : node.state.beaconChain.difficulty, "cumulatedDifficulty": node.state.beaconChain.cummulatedDifficulty, "IdealBlockTime": IdealBlockTime, "LastBlockTime": node.state.beaconChain.getLastBeacon().timestamp - node.state.beaconChain.getBlockByHeightJSON(int(len(node.state.beaconChain.blocks)-2))["timestamp"], "blockReward": BlockReward,  "target": node.state.beaconChain.miningTarget, "lastBlockHash": node.state.beaconChain.getLastBeacon().proof}}
    return jsonify(result=_stats_, success=True)

# HTTP GENERAL GETTERS - pulled from `Node` class
@app.get("/get/transactions") # get all transactions in node
def getTransactions():
    return jsonify(result=node.transactions, success=True)

@app.get("/get/nFirstTxs/{n}") # GET N first transactions
def nFirstTxs(n: int):
    _n = min(len(node.txsOrder), n)
    txs = []
    for txid in node.txsOrder[0:_n-1]:
        txs.append(node.transactions.get(txid))
    return jsonify(result=txs, success=True)

@app.get("/get/nLastTxs/{n}") # GET N last transactions
def nLastTxs(n: int):
    _n = min(len(node.txsOrder), n)
    _n = len(node.txsOrder)-_n
    txs = []
    for txid in node.txsOrder[_n:len(node.txsOrder)]:
        txs.append(node.transactions.get(txid))
    return jsonify(result=txs, success=True)

@app.get("/get/txsByBounds/{upperBound}/{lowerBound}") # get txs from upperBound to lowerBound (in index)
def getTxsByBound(upperBound, lowerBound):
    upperBound = min(upperBound, len(node.txsOrder)-1)
    lowerBound = max(lowerBound, 0)
    txs = []
    for txid in node.txsOrder[lowerBound,upperBound]:
        txs.append(node.transactions.get(txid))
    return jsonify(result=txs, success=True)

@app.get("/get/txIndex/{tx}")
def getTxIndex(tx):
    _index = node.state.txIndex.get(tx)
    if _index != None:
        return jsonify(result=_index, success=True)
    else:
        return (jsonify(message="TX_NOT_FOUND", success=False), 404)

@app.get("/get/transaction/{txhash}") # get specific tx by hash
def getTransactionByHash(txhash: str):
    tx = node.transactions.get(txhash)
    if (tx != None):
        return jsonify(result=tx, success=True)
    else:
        return (jsonify(message="TX_NOT_FOUND", success=False), 404)

@app.get("/get/transactions/{txhashes}") # get specific tx by hash
def getMultipleTransactionsByHashes(txhashes: str):
    txs = []
    oneSucceeded = False
    _txhashes = txhashes.split(",")
    for txhash in _txhashes:
        tx = node.transactions.get(txhash)
        if (tx):
            txs.append(tx)
            oneSucceeded = True
    return jsonify(result=txs, success=oneSucceeded)

@app.get("/get/numberOfReferencedTxs") # get number of referenced transactions
def numberOfTxs():
    return jsonify(result=len(node.txsOrder), success=True)



# ACCOUNT-BASED GETTERS (obtained from `State` class)
@app.get("/accounts/accountInfo/{account}") # Get account info (balance and transaction hashes)
def accountInfo(account: str):
    _address = w3.toChecksumAddress(account)
    balance = node.state.balances.get(_address)
    transactions = node.state.transactions.get(_address) or [node.config["InitTxID"]]
    bio = node.state.accountBios.get(_address)
    nonce = len(node.state.sent.get(_address) or ["init"])
    return jsonify({"balance": (balance or 0), "bio": bio or "", "nonce": nonce, "transactions": transactions}, success=True)

@app.get("/accounts/sent/{account}")
def sentByAccount(account: str):
    _address = w3.toChecksumAddress(account)
    return jsonify(result=node.state.sent.get(_address) or [], success= True)

@app.get("/accounts/accountBalance/{account}")
def accountBalance(account: str):
    _address = w3.toChecksumAddress(account)
    balance = node.state.balances.get(_address)
    return jsonify(result={"balance": (balance or 0)}, success=True)

@app.get("/accounts/txChilds/{tx}")
def txParent(tx: str):
    _kids = node.state.txChilds.get(tx)
    if _kids != None:
        return jsonify(result=_kids, success=True)
    else:
        return jsonify(message="TX_NOT_FOUND", success=False)

# SEND TRANSACTION STUFF (redirected to `Node` class)
@app.get("/send/rawtransaction/") # allows sending a raw (signed) transaction
def sendRawTransactions(tx: str = None):
    rawtxs = tx
    rawtxs = rawtxs.split(",")
    txs = []
    hashes = []
    for rawtx in rawtxs:
        tx = json.loads(bytes.fromhex(rawtx).decode())
        if (type(tx["data"]) == dict):
            tx["data"] = json.dumps(tx["data"]).replace(" ", "")
        txs.append(tx)
        hashes.append(tx["hash"])
    node.checkTxs(txs)
    return jsonify(result=hashes, success=True)

# BEACON RELATED DATA (loaded from node/state/beaconChain)
@app.get("/chain/block/{block}")
def getBlock(block: int):
    _block = node.state.beaconChain.getBlockByHeightJSON(block)
    return jsonify(result=_block, success=not not _block)

@app.get("/chain/blockByHash/{blockhash}")
def blockByHash(blockhash: str):
    _block = node.state.beaconChain.blocksByHash.get(blockhash)
    if _block:
        _block = _block.exportJson()
    return jsonify(result=_block, success=not not _block)

@app.get("/chain/getlastblock")
def getlastblock():
    return jsonify(result=node.state.beaconChain.getLastBlockJSON(), success=True)

@app.get("/chain/miningInfo")
def getMiningInfo():
    _result = {"difficulty" : node.state.beaconChain.difficulty, "target": node.state.beaconChain.miningTarget, "lastBlockHash": node.state.beaconChain.getLastBeacon().proof}
    return jsonify(result=_result, success=True)

@app.get("/chain/length")
def getChainLength():
    return jsonify(result=len(node.state.beaconChain.blocks), success=True)

# SHARE PEERS (from `Node` class)
@app.get("/net/getPeers")
def shareMyPeers():
    return jsonify(result=node.peers, success=True)

@app.get("/net/getOnlinePeers")
def shareOnlinePeers():
    return jsonify(result=node.goodPeers, success=True)

class Web3Body(pydantic.BaseModel):
    id: int
    method: str
    params: list


# WEB3 COMPATIBLE RPC
@app.post("/web3")
def handleWeb3Request(data: Web3Body):

    _id = data.id
    method = data.method
    params = data.params

    result = hex(Web3ChainID)
    if method == "eth_getBalance":
        result = hex(int((node.state.balances.get(w3.toChecksumAddress(params[0])) or 0)*10**18))
    if method == "net_version":
        result = str(Web3ChainID)
    if method == "eth_coinbase":
        result = node.state.beaconChain.getLastBeacon().miner
    if method == "eth_mining":
        result = False
    if method == "eth_gasPrice":
        result = "0x1"
    if method == "eth_blockNumber":
        result = hex(len(node.state.beaconChain.blocks) - 1)
    if method == "eth_getTransactionCount":
        result = hex(len(node.state.sent.get(w3.toChecksumAddress(params[0])) or []))
    if method == "eth_getCode":
        result = "0x"
    if method == "eth_estimateGas":
        result = '0x5208'
    if method == "eth_call":
        result = "0x"
    if method == "eth_getCompilers":
        result = []
    if method == "eth_sendRawTransaction":
        result = node.integrateETHTransaction(params[0])
    if method == "eth_getTransactionReceipt":
        result = node.txReceipt(params[0])

    return {"id": _id, "jsonrpc": "2.0", "result": result}

if __name__ == '__main__':
    uvicorn.run(app, host=nodeHost, port=nodePort)
