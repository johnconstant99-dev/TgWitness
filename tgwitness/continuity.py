"""Transactional Merkle index over event hashes; proofs disclose no message content.

Tree shape and proofs follow RFC 9162 section 2.1. This index is a cache, not a
trust anchor: offline verification recomputes roots from the signed events.
"""
from .verify import MERKLE_EMPTY, merkle_leaf, merkle_node


def index_event(connection, seq, event_hash):
    start, size, node = seq - 1, 1, merkle_leaf(event_hash)
    while True:
        connection.execute("INSERT INTO event_tree(start,size,hash) VALUES (?,?,?)", (start, size, node))
        if not start & size:
            break
        left = connection.execute("SELECT hash FROM event_tree WHERE start=? AND size=?",
                                  (start - size, size)).fetchone()
        if left is None:
            raise ValueError("Incomplete journal Merkle index")
        node, start, size = merkle_node(left[0], node), start - size, size * 2


def initialize(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS event_tree (start INTEGER NOT NULL, size INTEGER NOT NULL,"
                       "hash BLOB NOT NULL, PRIMARY KEY(start,size)) WITHOUT ROWID")

    indexed = connection.execute("SELECT coalesce(max(start)+1,0) FROM event_tree WHERE size=1").fetchone()[0]
    for row in connection.execute("SELECT seq,hash FROM events WHERE seq>? ORDER BY seq", (indexed,)):
        if row[0] != indexed + 1:
            raise ValueError("Journal is not contiguous; cannot build Merkle index")
        index_event(connection, row[0], row[1])
        indexed += 1


class Tree:
    """Read a tree from the same SQLite snapshot as its checkpoint and counters."""
    def __init__(self, connection):
        self.connection = connection

    def root(self, start, size):
        if size == 0:
            return MERKLE_EMPTY
        if size & (size - 1) == 0:
            row = self.connection.execute("SELECT hash FROM event_tree WHERE start=? AND size=?", (start, size)).fetchone()
            if row is None:
                raise ValueError("Missing journal Merkle node")
            return row[0]
        split = 1 << (size.bit_length() - 1)
        return merkle_node(self.root(start, split), self.root(start + split, size - split))

    def inclusion(self, index, size, start=0):
        if not 0 <= index < size:
            raise ValueError("Merkle leaf outside journal")
        if size == 1:
            return []
        split = 1 << ((size - 1).bit_length() - 1)
        if index < split:
            return self.inclusion(index, split, start) + [self.root(start + split, size - split).hex()]
        return self.inclusion(index - split, size - split, start + split) + [self.root(start, split).hex()]

    def consistency(self, first, second, start=0, known=True):
        if not 0 <= first <= second:
            raise ValueError("Invalid Merkle tree sizes")
        if first == 0:
            return []
        if first == second:
            return [] if known else [self.root(start, second).hex()]
        split = 1 << ((second - 1).bit_length() - 1)
        if first <= split:
            return self.consistency(first, split, start, known) + [self.root(start + split, second - split).hex()]
        return self.consistency(first - split, second - split, start + split, False) + [self.root(start, split).hex()]


def answer(snapshot, vault, challenge, previous_count):
    count = snapshot.head["seq"] if snapshot.head else 0


    previous_count = min(previous_count, count)
    tree = Tree(snapshot.connection)
    statement = {"format": "tgwitness-continuity-v1", "public_key": vault.public_key,
                 "event_count": count, "head_hash": snapshot.head["hash"] if snapshot.head else "0" * 64,
                 "root": tree.root(0, count).hex(), "challenge": challenge}
    from .store import canonical
    return {"statement": statement, "signature": vault.sign(canonical(statement)), "proof": {
        "from_count": previous_count, "consistency": tree.consistency(previous_count, count),
        "head_path": tree.inclusion(count - 1, count) if count else [],
        "previous_head_path": tree.inclusion(previous_count - 1, count) if previous_count else []}}
