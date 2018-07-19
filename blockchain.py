import json
import logging
import socket
import time
import hashlib
import Crypto.PublicKey.RSA as RSA
from datetime import datetime
from threading import Thread

from flask import Flask, jsonify

class Block(object):
    def __init__(self, index, previous_hash, timestamp, data, nonce, hashvalue=''):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = hashvalue

    def calculate_hash(self):
        hash_cal = hashlib.sha256()
        hash_cal.update(str(self.index) + str(self.previous_hash)
         + str(self.timestamp) + str(self.data) + str(self.nonce)) 
        return hash_cal.digest()

    @staticmethod
    def from_previous(block, data):
        return Block(block.index + 1, block.hash, datetime.now(), data, 0)

    @staticmethod
    def from_json(block):
        block = Block(**block)
        assert block.calculate_hash() == block.hash
        return block

    def __repr__(self):
        return str(self.__dict__)


GENESIS = Block(
    0, '', 1522983367254, None, 0,
    'e063dac549f070b523b0cb724efb1d4f81de67ea790f78419f9527aa3450f64c'
)


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


class Server(object):
    def __init__(self):
        self.blocks = [GENESIS]
        self.peers = {}

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_logger = logging.getLogger('UDP')

        self.http = Flask(__name__)
        self.http.config.from_object(self)
        self.http.json_encoder = JSONEncoder
        self.http.route('/blocks', methods=['GET'])(self.list_blocks)
        self.http.route('/peers', methods=['GET'])(self.list_peers)
        self.http.route('/blocks', methods=['POST'])(self.add_blocks)
        self.http.route('/transactions', methods=['POST'])(self.add_transactions)
        self.http.route('/account', methods=['GET'])(self.create_account)

    def list_blocks(self):
        return jsonify(self.blocks)

    def list_peers(self):
        return jsonify(self.peers)

    def add_blocks(self):
        # TODO
        pass

    def create_account(self):
        key = RSA.generate(1024)
        pubkey = key.publickey().exportKey('PEM').hex()
        prikey = key.exportKey('PEM').hex()
        args = {'publickey': pubkey, 'privatekey': prikey}
        return jsonify(args)

    def add_transactions(self):
        # TODO
        pass
        # from: 'account', to: '', amount: 25, signature: '', 

    def run(self, host='0.0.0.0'):
        logging.info('Starting...')
        self.udp.bind((host, 2346))
        udp_listen = Thread(target=self.udp_listen)
        udp_broadcast = Thread(target=self.udp_broadcast)
        udp_listen.start()
        udp_broadcast.start()

        self.http.run(host=host, port=2345)
        udp_listen.join()
        udp_broadcast.join()

    def udp_broadcast(self):
        while True:
            self.udp.sendto(b'hello', ('255.255.255.255', 2346))
            time.sleep(1)

    def udp_listen(self):
        while True:
            message, remote = self.udp.recvfrom(8)
            address, _ = remote
            self.udp_logger.debug([message, remote])
            if message == b'hello' and address not in self.peers:
                self.peers[address] = remote
                self.udp_logger.info('Peer discovered: %s', remote)
