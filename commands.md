<<<<<<< HEAD
docker compose build .
docker compose up

visit below blockchain urls :
| URL | Description |
| -------------------- | ---------------------------------------------------------------- |
| `localhost:5000/` | Default route, returns a welcome message |
| `localhost:5000/blockchain` | Returns the full blockchain as JSON |
| `localhost:5000/blockchain/range` | Returns a slice of the blockchain (query params: `start`, `end`) |
| `localhost:5000/blockchain/length` | Returns the length of the blockchain |
| `localhost:5000/blockchain/mine` | Mines a block with transactions from the pool |
| `localhost:5000/wallet/info` | Returns wallet address and balance |
| `localhost:5000/known-addresses` | Returns all known wallet addresses in the blockchain |
| `localhost:5000/transactions` | Returns all transactions in the pool |

Note : localhost:5001 , 5002 , and 5003 are synced nodes.

visit below app urls : (WIP)
localhost:8000/api/
=======
docker exec -it a62aff25a4bb python manage.py ingest_chain --base http://host.docker.internal:5000 --save-metadata

> > > > > > > c56c06d ( Slightly modified 2025)

ubuntu@ip-172-31-12-54:~/cuddly-hex/miners$ export MINER_TOKEN="secret123"
ubuntu@ip-172-31-12-54:~/cuddly-hex/miners$ export MINER_TOKEN_HEADER="Authorization" # or "X-Miner-Token"
ubuntu@ip-172-31-12-54:~/cuddly-hex/miners$ PYTHONPATH=.. python3 simple_miner.py --node http://127.0.0.1:5000 --addr miner-demo-addr
git fetch --all
git checkout master
git reset --hard origin/master
python -m miners.simple_miner --node http://127.0.0.1:5000 --addr miner-demo-addr --debug-dir ./debug --token secret123
ssh -i "MSI AWS.pem" ubuntu@3.108.252.40

Run miner local : MINER_NODE_URL="http://127.0.0.1:5000" MINER_TOKEN="secret123" MINER_REWARD_ADDRESS="miner-demo-addr" MINER_INTERVAL=2 MINER_ALLOW_EMPTY=0 python3 -m miners.simple_miner --node http://127.0.0.1:5000 --addr miner-demo-addr


mkdir -p ./data/node0/leveldb ./data/node1/leveldb ./data/node2/leveldb ./data/node3/leveldb
sudo chown -R 1000:1000 ./data/node*/leveldb   # adjust UID/GID to match your container user
chmod -R 770 ./data/node*/leveldb