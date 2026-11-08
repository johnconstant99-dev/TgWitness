import base64
import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

ROUNDS = 24
ROTATIONS = (1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44)
PIECES = (10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1)
CONSTANTS = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
             0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
             0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
             0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
             0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
MASK = (1 << 64) - 1
RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
XRP_WORD = re.compile(r"(?<![A-Za-z0-9])r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}"
                      r"(?![A-Za-z0-9])")
EVM_TX = re.compile(r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{64}(?![A-Za-z0-9])")
BARE_HASH = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{64}(?![A-Za-z0-9])")
TX_CONTEXT = re.compile(r"(?i)\b(tx|txid|txn|hash|transaction|transfer|receipt|explorer|tronscan|etherscan|blockchair|"
                        r"mempool|solscan|tonscan|транзакц\w*|хеш\w*|хэш\w*|перевод\w*|квитанц\w*)\b")
URI = re.compile(r"(?i)(?<![\w.-])(?:bitcoin|ethereum|solana|tron|litecoin|dogecoin|ton):(?://)?[^\s<>\"'`«»“”]+")
EXPLORERS = {"Bitcoin": "https://mempool.space/tx/", "Ethereum": "https://etherscan.io/tx/",
             "TRON": "https://tronscan.org/#/transaction/", "Solana": "https://solscan.io/tx/",
             "TON": "https://tonviewer.com/transaction/", "XRP": "https://xrpscan.com/tx/"}
URI_CHAINS = {"bitcoin": "Bitcoin", "ethereum": "EVM", "solana": "Solana", "tron": "TRON", "litecoin": "Litecoin",
              "dogecoin": "Dogecoin", "ton": "TON"}
EVM_CHAIN_IDS = {"1": "Ethereum", "10": "Optimism", "56": "BNB Chain", "137": "Polygon", "8453": "Base",
                 "42161": "Arbitrum One", "43114": "Avalanche C-Chain"}


def keccak256(data):
    rate, state = 136, [0] * 25
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * ((-len(padded)) % rate)
    padded[-1] |= 0x80
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(block[index * 8:index * 8 + 8], "little")
        state = permute(state)
    out = b"".join(state[index].to_bytes(8, "little") for index in range(4))
    return out[:32]


def permute(state):
    for round_index in range(ROUNDS):
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        for x in range(5):
            mixed = columns[x - 4 if x < 4 else 0]
            spread = columns[x - 1] ^ (((mixed << 1) | (mixed >> 63)) & MASK)
            for y in range(0, 25, 5):
                state[y + x] ^= spread
        carried, lane = state[1], [0] * 25
        lane[0] = state[0]
        for step in range(ROUNDS):
            target = PIECES[step]
            shift = ROTATIONS[step]
            keep = state[target]
            lane[target] = ((carried << shift) | (carried >> (64 - shift))) & MASK
            carried = keep
        for y in range(0, 25, 5):
            row = lane[y:y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ ((~row[(x + 1) % 5]) & MASK & row[(x + 2) % 5])
        state[0] ^= CONSTANTS[round_index]
    return state


def eip55(address):
    body = address[2:]
    digest = keccak256(body.lower().encode()).hex()
    return "0x" + "".join(char.upper() if char.isalpha() and int(digest[index], 16) >= 8 else char.lower()
                          for index, char in enumerate(body))


def evm_checksum(address):
    body = address[2:]
    if body == body.lower() or body == body.upper():
        return "none"
    return "valid" if eip55(address) == address else "failed"


def ripple_decode(text):
    number = 0
    for char in text:
        number = number * 58 + RIPPLE.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("r"))) + body


def xrp_valid(text):
    try:
        data = ripple_decode(text)
    except ValueError:
        return False
    if len(data) != 25 or data[0] != 0x00:
        return False
    return hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4] == data[-4:]


def ton_raw(address):
    try:
        data = base64.urlsafe_b64decode(address.replace("+", "-").replace("/", "_") + "=" * (-len(address) % 4))
    except (ValueError, TypeError):
        return None
    if len(data) != 36:
        return None
    workchain = data[1] - 256 if data[1] > 127 else data[1]
    return "%d:%s" % (workchain, data[2:34].hex())


def normalise(value, chain):
    if chain == "TON":
        if ":" in value:
            workchain, body = value.split(":", 1)
            return "%d:%s" % (int(workchain), body.lower())
        return ton_raw(value) or value
    if chain and chain.startswith("EVM") or chain in EVM_CHAIN_IDS.values():
        return value.lower()
    return value


def transactions(text):
    found, context = [], bool(TX_CONTEXT.search(text))
    for match in EVM_TX.finditer(text):
        found.append({"value": match.group(0).lower(), "chain": "EVM", "form": "32-byte hash with 0x",
                      "explorer": EXPLORERS["Ethereum"] + match.group(0).lower()})
    if context:
        seen = {item["value"][2:] for item in found}
        for match in BARE_HASH.finditer(text):
            value = match.group(0).lower()
            if value not in seen:
                found.append({"value": value, "chain": None, "form": "64 hexadecimal characters",
                              "note": "The chain is not stated; the same shape is used by Bitcoin, TRON, TON and "
                                      "others. Resolve it against an explorer before relying on it."})
    return found


def payment_uris(text):
    found = []
    for match in URI.finditer(text):
        parsed = urlsplit(match.group(0).rstrip(".,;:!?)]}>"))
        scheme = parsed.scheme.lower()
        target = (parsed.netloc + parsed.path).strip("/")
        query = dict(parse_qsl(parsed.query))
        chain = URI_CHAINS.get(scheme)
        if scheme == "ton":
            target = target.removeprefix("transfer/")
        contract = None
        if scheme == "ethereum":
            target, _, network = target.partition("@")
            function = network.partition("/")[2]
            chain = EVM_CHAIN_IDS.get(network.split("/")[0], "EVM")
            if function.startswith("transfer") and query.get("address"):
                contract, target = target, query["address"]
        target = target.split("/")[0]
        if not target:
            continue
        entry = {"uri": match.group(0), "chain": chain, "address": target, "token_contract": contract,
                 "amount": query.get("amount") or query.get("uint256") or query.get("value"),
                 "token": query.get("spl-token") or query.get("token"), "label": query.get("label") or query.get("text")}
        found.append({key: value for key, value in entry.items() if value})
    return found


def extra(address, chain):
    if chain and chain.startswith("EVM"):
        return {"checksum": evm_checksum(address), "normalized": address.lower(),
                "chain_note": "The same address exists on every EVM network; the chain follows from the context."}
    if chain == "TON":
        return {"normalized": normalise(address, "TON"),
                "chain_note": "One TON account has several spellings; the raw form identifies it."}
    return {}
