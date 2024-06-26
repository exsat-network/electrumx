import struct
from enum import IntEnum
from typing import Optional, Callable, Union, Tuple, Sequence

from . import constants
from . import segwit_addr
from .crypto import sha256d, to_bytes, hash_160, sha256


class MalformedBitcoinScript(Exception):
    pass

class opcodes(IntEnum):
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    OP_INVALIDOPCODE = 0xff

    def hex(self) -> str:
        return bytes([self]).hex()



def script_GetOp(_bytes : bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                try: nSize = _bytes[i]
                except IndexError: raise MalformedBitcoinScript()
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                try: (nSize,) = struct.unpack_from('<H', _bytes, i)
                except struct.error: raise MalformedBitcoinScript()
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                try: (nSize,) = struct.unpack_from('<I', _bytes, i)
                except struct.error: raise MalformedBitcoinScript()
                i += 4
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable=None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        return opcodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))



class OPGeneric:
    def __init__(self, matcher: Callable=None):
        if matcher is not None:
            self.matcher = matcher

    def match(self, op) -> bool:
        return self.matcher(op)

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))

OPPushDataPubkey = OPPushDataGeneric(lambda x: x in (33, 65))
OP_ANYSEGWIT_VERSION = OPGeneric(lambda x: x in list(range(opcodes.OP_1, opcodes.OP_16 + 1)))

SCRIPTPUBKEY_TEMPLATE_P2PKH = [opcodes.OP_DUP, opcodes.OP_HASH160,
                               OPPushDataGeneric(lambda x: x == 20),
                               opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
SCRIPTPUBKEY_TEMPLATE_P2SH = [opcodes.OP_HASH160, OPPushDataGeneric(lambda x: x == 20), opcodes.OP_EQUAL]
SCRIPTPUBKEY_TEMPLATE_WITNESS_V0 = [opcodes.OP_0, OPPushDataGeneric(lambda x: x in (20, 32))]
SCRIPTPUBKEY_TEMPLATE_P2WPKH = [opcodes.OP_0, OPPushDataGeneric(lambda x: x == 20)]
SCRIPTPUBKEY_TEMPLATE_P2WSH = [opcodes.OP_0, OPPushDataGeneric(lambda x: x == 32)]
SCRIPTPUBKEY_TEMPLATE_ANYSEGWIT = [OP_ANYSEGWIT_VERSION, OPPushDataGeneric(lambda x: x in list(range(2, 40 + 1)))]



def match_script_against_template(script, template, debug=False) -> bool:
    """Returns whether 'script' matches 'template'."""
    if script is None:
        return False
    # optionally decode script now:
    if isinstance(script, (bytes, bytearray)):
        try:
            script = [x for x in script_GetOp(script)]
        except MalformedBitcoinScript:
            if debug:
                print(f"malformed script")
            return False
    if debug:
        print(f"match script against template: {script}")
    if len(script) != len(template):
        if debug:
            print(f"length mismatch {len(script)} != {len(template)}")
        return False
    for i in range(len(script)):
        template_item = template[i]
        script_item = script[i]
        if OPPushDataGeneric.is_instance(template_item) and template_item.check_data_len(script_item[0]):
            continue
        if OPGeneric.is_instance(template_item) and template_item.match(script_item[0]):
            continue
        if template_item != script_item[0]:
            if debug:
                print(f"item mismatch at position {i}: {template_item} != {script_item[0]}")
            return False
    return True

class BitcoinException(Exception): pass

def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except Exception:
        print('assert bytes failed', list(map(type, args)))
        raise

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58
__b58chars_inv = constants.inv_dict(dict(enumerate(__b58chars)))

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43
__b43chars_inv = constants.inv_dict(dict(enumerate(__b43chars)))


class BaseDecodeError(BitcoinException): pass


def base_encode(v: bytes, *, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars

    origlen = len(v)
    v = v.lstrip(b'\x00')
    newlen = len(v)

    num = int.from_bytes(v, byteorder='big')
    string = b""
    while num:
        num, idx = divmod(num, base)
        string = chars[idx:idx + 1] + string

    result = chars[0:1] * (origlen - newlen) + string
    return result.decode('ascii')


def base_decode(v: Union[bytes, str], *, base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes.

    based on the work of David Keijser in https://github.com/keis/base58
    """
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    chars_inv = __b58chars_inv
    if base == 43:
        chars = __b43chars
        chars_inv = __b43chars_inv

    origlen = len(v)
    v = v.lstrip(chars[0:1])
    newlen = len(v)

    num = 0
    try:
        for char in v:
            num = num * base + chars_inv[char]
    except KeyError:
        raise BaseDecodeError('Forbidden character {} for base {}'.format(char, base))

    return num.to_bytes(origlen - newlen + (num.bit_length() + 7) // 8, 'big')


class InvalidChecksum(BaseDecodeError):
    pass


def EncodeBase58Check(vchIn: bytes) -> str:
    hash = sha256d(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def DecodeBase58Check(psz: Union[bytes, str]) -> bytes:
    vchRet = base_decode(psz, base=58)
    payload = vchRet[0:-4]
    csum_found = vchRet[-4:]
    csum_calculated = sha256d(payload)[0:4]
    if csum_calculated != csum_found:
        raise InvalidChecksum(f'calculated {csum_calculated.hex()}, found {csum_found.hex()}')
    else:
        return payload


def hash160_to_b58_address(h160: bytes, addrtype: int) -> str:
    s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def b58_address_to_hash160(addr: str) -> Tuple[int, bytes]:
    addr = to_bytes(addr, 'ascii')
    _bytes = DecodeBase58Check(addr)
    if len(_bytes) != 21:
        raise Exception(f'expected 21 payload bytes in base58 address. got: {len(_bytes)}')
    return _bytes[0], _bytes[1:21]



def hash160_to_p2pkh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2PKH)

def hash160_to_p2sh(h160: bytes, *, net=None) -> str:
    if net is None: net = constants.net
    return hash160_to_b58_address(h160, net.ADDRTYPE_P2SH)

def public_key_to_p2pkh(public_key: bytes, *, net=None) -> str:
    return hash160_to_p2pkh(hash_160(public_key), net=net)

def hash_to_segwit_addr(h: bytes, witver: int, *, net=None) -> str:
    if net is None: net = constants.net
    addr = segwit_addr.encode_segwit_address(net.SEGWIT_HRP, witver, h)
    assert addr is not None
    return addr

def public_key_to_p2wpkh(public_key: bytes, *, net=None) -> str:
    return hash_to_segwit_addr(hash_160(public_key), witver=0, net=net)

def script_to_p2wsh(script: bytes, *, net=None) -> str:
    return hash_to_segwit_addr(sha256(script), witver=0, net=net)


def get_address_from_output_script(_bytes: bytes, *, net=None) -> Optional[str]:
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        return None

    # p2pkh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2PKH):
        return hash160_to_p2pkh(decoded[2][1], net=net)

    # p2sh
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_P2SH):
        return hash160_to_p2sh(decoded[1][1], net=net)

    # segwit address (version 0)
    if match_script_against_template(decoded, SCRIPTPUBKEY_TEMPLATE_WITNESS_V0):
        return hash_to_segwit_addr(decoded[1][1], witver=0, net=net)

    # segwit address (version 1-16)
    future_witness_versions = list(range(opcodes.OP_1, opcodes.OP_16 + 1))
    for witver, opcode in enumerate(future_witness_versions, start=1):
        match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
        if match_script_against_template(decoded, match):
            return hash_to_segwit_addr(decoded[1][1], witver=witver, net=net)

    return None
