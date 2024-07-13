.. image:: https://api.cirrus-ci.com/github/spesmilo/electrumx.svg?branch=master
    :target: https://cirrus-ci.com/github/spesmilo/electrumx
.. image:: https://coveralls.io/repos/github/spesmilo/electrumx/badge.svg
    :target: https://coveralls.io/github/spesmilo/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================

  :Licence: MIT
  :Language: Python (>= 3.8)
  :Original Author: Neil Booth

This project is a fork of `kyuupichan/electrumx <https://github.com/kyuupichan/electrumx>`_.
The original author dropped support for Bitcoin, which we intend to keep.

ElectrumX allows users to run their own Electrum server. It connects to your
full node and indexes the blockchain, allowing efficient querying of the history of
arbitrary addresses. The server can be exposed publicly, and joined to the public network
of servers via peer discovery. As of May 2020, a significant chunk of the public
Electrum server network runs ElectrumX.

Documentation
=============

See `readthedocs <https://electrumx-spesmilo.readthedocs.io/>`_.

Install
=============

.. code-block:: shell

    git clone https://github.com/exsat-network/electrumx.git
    cd electrumx
    python3 -m venv venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt

Edit .env
=============

.. code-block:: shell

    DAEMON_URL=http://<bitcoinrpcuser>:<bitcoinrpcpassword>@localhost:8332
    COIN=Bitcoin
    REQUEST_TIMEOUT=25
    DB_DIRECTORY=<Your DB PATH>
    DB_ENGINE=leveldb
    SERVICES=tcp://0.0.0.0:50011=0,ws://:50020,rpc://:8000,http://:8080
    HOST=""
    ALLOW_ROOT=true
    CACHE_MB=400
    MAX_SEND=3000000
    COST_SOFT_LIMIT=100000
    COST_HARD_LIMIT=1000000
    REQUEST_SLEEP=100
    INITIAL_CONCURRENT=10
    ENABLE_RATE_LIMIT=false
    END_BLOCK=839999

Run
=============

.. code-block:: shell

    # open a window
    tmux new -s elec
    source ./venv/bin/activate
    ./electrumx_server

