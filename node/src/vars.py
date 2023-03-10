import mock, yaml

file_paths = mock.Mock()
file_paths.config = "data/config.yaml"
file_paths.peerlist = "data/peerlist.json"
file_paths.database = "data/database.json"
file_paths.privkey = "data/acc.priv"

Web3ChainID = 5151
CoinName = "MadzCoin"
IdealBlockTime = 300
BlockReward = 10.5

data = yaml.safe_load(open(file_paths.config))

MOTD = data["config"]["MOTD"]
VER = "0.14"
