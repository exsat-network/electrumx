from electrumx.script import constants
from electrumx.script.script import address_to_script, script_to_address

def test_script():
    constants.set_mainnet()
    p2wpkh_script_hash = address_to_script("bc1qmenyusy58ulktrpcxhrfd9s89jt4gvl3uvm5f8")
    p2sh_p2wpkh_script_hash = address_to_script("32PMRR41aGEkVgngo5wPYr1qDyoQyb3MT5")
    taproot_script_hash = address_to_script("bc1pg5pk4aaqfalzsd89u2phndt67jdhsp23xj5fvtaqdxqkwhs3pqvqtz92v5")
    p2pkh_hash = address_to_script("15qc2jigN5uQSE75R7EeERCwfeEjZqTQU6")


    print("p2wpkh_script_hash=",p2wpkh_script_hash.hex())
    print("p2sh_p2wpkh_script_hash=",p2sh_p2wpkh_script_hash.hex())
    print("taproot_script_hash=",taproot_script_hash.hex())
    print("p2pkh_hash=",p2pkh_hash.hex())

    p2wpkh = script_to_address(p2wpkh_script_hash)
    p2sh_p2wpkh = script_to_address(p2sh_p2wpkh_script_hash)
    taproot = script_to_address(taproot_script_hash)
    p2pkh = script_to_address(p2pkh_hash)

    print("p2wpkh=",p2wpkh)
    print("p2sh_p2wpkh=",p2sh_p2wpkh)
    print("taproot=",taproot)
    print("p2pkh=",p2pkh)
