"""A larger, freshly signed journal must extend the witness's retained Merkle tree."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.capture_proof import capture_head  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402
from tgwitness.verify import fingerprint  # noqa: E402
from tgwitness.witness import InvalidAnswer, Witness  # noqa: E402


def test_rewritten_1000_record_prefix_is_rejected_when_the_journal_grows_to_1100(tmp_path):
    vault = Vault(tmp_path / 'original')
    (tmp_path / 'rewritten').mkdir()
    original, rewritten = Store(tmp_path / 'original'), Store(tmp_path / 'rewritten')
    original.bind(vault)
    rewritten.bind(vault)
    observer = Witness(tmp_path / 'observer', 'https://collector.invalid', 'synthetic', pinned=fingerprint(vault.public_key))
    try:
        for index in range(1000):
            original.append('message.new', {'text': 'Original ' + str(index)}, -1000000000001, index + 1)
        first = capture_head(original, vault, {}, 'a' * 32, consistency_from=0)
        assert observer.check(first)['continuity_status'] == 'baseline'
        retained = observer.store.get_setting('last_seen')
        for index in range(1100):
            rewritten.append('message.new', {'text': 'Changed first record' if index == 0 else 'Original ' + str(index)},
                             -1000000000001, index + 1)
        forged = capture_head(rewritten, vault, {}, 'b' * 32, consistency_from=1000)
        with pytest.raises(InvalidAnswer, match='continuity failed'):
            observer.check(forged)
        assert observer.store.get_setting('last_seen') == retained
        for index in range(1000, 1100):
            original.append('message.new', {'text': 'Original ' + str(index)}, -1000000000001, index + 1)
        good = capture_head(original, vault, {}, 'c' * 32, consistency_from=1000)
        assert observer.check(good)['continuity_status'] == 'extended'
        good.pop('continuity')
        with pytest.raises(InvalidAnswer, match='removed the required'):
            observer.check(good)
    finally:
        observer.close()
        original.close()
        rewritten.close()


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
