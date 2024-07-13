# -*- coding: utf-8 -*-

from aiohttp import web
import electrumx.lib.util as util
from electrumx.lib.hash import hash_to_hex_str, Base58
from electrumx.script.script import get_address_from_output_script


class HttpHandler(object):
    PROTOCOL_MIN = (1, 4)
    PROTOCOL_MAX = (1, 4, 3)

    def __init__(self, db, daemon):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.db = db
        self.daemon = daemon

    async def all_utxos(self, request):
        startkey = request.query.get("startkey", None)
        limit = request.query.get("limit", 10)
        limit = int(limit)
        last_db_key, utxos = await self.db.pageable_utxos(startkey, limit)
        data_list = []

        for utxo in utxos:
            txid = hash_to_hex_str(utxo.tx_hash)
            scriptPubKeyHex = utxo.pk_script.hex()
            bitcoin_address = get_address_from_output_script(utxo.pk_script)

            data = {'height': utxo.height,
                    'address': bitcoin_address,
                    'scriptPubKey': scriptPubKeyHex,
                    'txid': txid,
                    'vout': utxo.tx_pos,
                    'value': utxo.value}
            data_list.append(data)

        res = {'last_key': last_db_key, 'utxos': data_list}
        return web.json_response(res)

    async def count_utxos(self, request):
        count = await self.db.count_utxos()
        res = {'utxo_count': count}
        return web.json_response(res)
