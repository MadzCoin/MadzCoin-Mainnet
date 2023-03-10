"""
    Madzcoin Core V 0.14
    Copyright (c) 2023 The Madzcoin developers
    Distributed under the MIT software license, see the accompanying
    For copying see http://opensource.org/licenses/mit-license.php.
"""

import os

import fastapi
import pydantic
import requests
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from src.core import *


def jsonify(result = None, success = True, message = None):
    if not result == None:
        return {"result": result, "success": success}
    elif not message == None:
        return {"message": message, "success": success}


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

######################### Web ###########################
@app.get("/")
def basicInfoHttp():
    return  f"{MOTD or 'No MOTD defined :('}"

@app.get("/ping")
def getping():
    return {"result": "Pong!", "success": True}

@app.get("/stats")
def getStats():
    _stats_ = {"coin": {"transactions": len(node.txsOrder), "supply": node.state.totalSupply, "holders": len(node.state.holders)}, "chain": {"length": len(node.state.beaconChain.blocks), "difficulty": node.state.beaconChain.difficulty, "cumulatedDifficulty": node.state.beaconChain.cummulatedDifficulty, "IdealBlockTime": IdealBlockTime, "LastBlockTime": node.state.beaconChain.getLastBeacon().timestamp - node.state.beaconChain.getBlockByHeightJSON(int(len(node.state.beaconChain.blocks)-2))["timestamp"], "blockReward": BlockReward,  "target": node.state.beaconChain.miningTarget, "lastBlockHash": node.state.beaconChain.getLastBeacon().proof}, "node": {"owner": PUB_KEY, "last_registration_tx": REG_TXID, "version": VER}}
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
    for txid in node.txsOrder[lowerBound, upperBound]:
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
    if tx != None:
        return jsonify(result=tx, success=True)
    else:
        return (jsonify(message="TX_NOT_FOUND", success=False), 404)

@app.get("/get/transactionByBlockHash/{block_hash}")
def get_tx_from_blockhash(block_hash: str):
    block = node.state.beaconChain.blocksByHash.get(block_hash)
    if block:
        block = block.exportJson()
        transactions = node.state.transactions.get(block["miningData"]["miner"])
        transactions.reverse()
        for transaction in transactions:
            if transaction != "none":
                transaction = node.transactions.get(transaction)
                transaction_data = json.loads(transaction["data"])
                if transaction_data["type"] == 1:
                    if transaction_data["blockData"]["miningData"]["proof"] == block_hash:
                        return jsonify(result=transaction, success=True)



@app.get("/get/transactions/{txhashes}") # get specific tx by hash
def getMultipleTransactionsByHashes(txhashes: str):
    txs = []
    oneSucceeded = False
    _txhashes = txhashes.split(",")
    for txhash in _txhashes:
        tx = node.transactions.get(txhash)
        if tx:
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
    transactions = node.state.transactions.get(_address) or ['none']
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

        if type(tx["data"]) == dict:
            tx["data"] = json.dumps(tx["data"]).replace(" ", "")


        dict_data = json.loads(tx["data"])

        if dict_data["type"] == 1:
            peer_above_height_is_valid = False                                                                                                                          #As it's type 1, it may cause syncing interuptions, check if other nodes are above height
            node_last_block = node.state.beaconChain.getBlockByHeightJSON(len(node.state.beaconChain.blocks) - 2)
            for peer in peer_discovery("").peerupdate(): #Public node not defined, as it won't be used
                try:
                    peer_stats = requests.get(peer + "/stats")
                    if peer_stats.status_code == 200:
                        peer_stats = peer_stats.json()["result"]
                        peer_last_block = requests.get(peer + "chain/block/" + str(len(node.state.beaconChain.blocks) - 2))
                        if peer_last_block.status_code == 200:
                            peer_last_block = peer_last_block.json()["result"]
                            peer_node_height_delta = peer_stats["chain"]["length"] - len(node.state.beaconChain.blocks)
                            if peer_last_block == node_last_block and peer_node_height_delta > 0:
                                _tx = requests.get(peer + "/get/transactionByBlockHash/" + peer_stats["chain"]["lastBlockHash"])
                                if _tx.status_code == 200:
                                    _tx = json.loads(_tx.json()["result"]["data"])
                                    targets_match = True
                                    if peer_node_height_delta == 1:
                                        targets_match = _tx["blockData"]["miningData"]["miningTarget"] == dict_data["blockData"]["miningData"]["miningTarget"]

                                    peer_above_height_is_valid = State().estimateMiningSuccess(Transaction(_tx), diff=peer_stats["chain"]["difficulty"]) and targets_match

                                    if peer_above_height_is_valid:
                                        break
                except Exception as ex:
                    if requests.exceptions.RequestException:
                        pass
                    else:
                        raise ex

            if not peer_above_height_is_valid:
                txs.append(tx)
                hashes.append(tx["hash"])

        else:               #Don't worry about checking if any nodes are ahead, just save it
            txs.append(tx)
            hashes.append(tx["hash"])

    node.checkTxs(txs)
    return jsonify(result=hashes, success=True)

# BEACON RELATED DATA (loaded from node/state/beaconChain)
@app.get("/chain/block/{block}")
def getBlock(block: int):
    _block = node.state.beaconChain.getBlockByHeightJSON(block)
    return jsonify(result=_block, success=bool(_block))

@app.get("/chain/blockByHash/{blockhash}")
def blockByHash(blockhash: str):
    _block = node.state.beaconChain.blocksByHash.get(blockhash)
    if _block:
        _block = _block.exportJson()
    return jsonify(result=_block, success=bool(_block))

@app.get("/chain/getlastblock")
def getlastblock():
    return jsonify(result=node.state.beaconChain.getLastBlockJSON(), success=True)

@app.get("/chain/miningInfo")
def getMiningInfo():
    _result = {"difficulty": node.state.beaconChain.difficulty, "target": node.state.beaconChain.miningTarget, "lastBlockHash": node.state.beaconChain.getLastBeacon().proof}
    return jsonify(result=_result, success=True)

@app.get("/chain/length")
def getChainLength():
    return jsonify(result=len(node.state.beaconChain.blocks), success=True)

# Peers
@app.get("/NodeVer")
def nodever():
    return jsonify(result=VER, success=True)

@app.get("/net/getPeers")
def shareMyPeers():
    return jsonify(result=node.peerlist, success=True)

@app.get("/net/getOnlinePeers")
def shareOnlinePeers():
    return jsonify(result=node.goodPeers, success=True)

@app.get("/net/verify")
def create_upload_file():
    try:
        with open("database.json","r") as f:
            contents = f.readlines()
    except Exception:
        return jsonify(result="There was an error uploading the file", success=False)

    return contents

@app.post("/net/NewPeer")
async def newnodes(request: fastapi.Request):
    peer_url = (await request.body()).decode("utf-8") 
    peer_discovery(read_yaml_config(print_host = False)[0]).check_add_peer(peer_url)


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


def runNode():
    if os.path.exists(file_paths.config):
        public_node, private_node, ssl_cfg = read_yaml_config()

        def start():
            rgbPrint(f"Public host: {public_node['url']}", "green", end="\n")
            rgbPrint(f"Pruning Nodes from {file_paths.peerlist}", "green", end="\n"*2)
            uvicorn.run(app, host = private_node["host"], port = private_node["port"], ssl_keyfile = ssl_cfg["ssl_keyfile"], ssl_certfile = ssl_cfg["ssl_certfile"], ssl_ca_certs = ssl_cfg["ssl_ca_certs"])

        t1 = threading.Thread(target=start)
        t1.start()
        t1.join()

    else:
        rgbPrint(f"Config file: {file_paths.config} does not exist!")
