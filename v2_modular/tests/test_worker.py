"""工作线程信号合约：批次、取消、失败与资源释放。"""

from collections import Counter

import pytest

pytest.importorskip("PyQt5")
from log_analyzer.gui import worker as workers
from log_analyzer.models import Finding, GeoInfo, SourceEntry
from log_analyzer.rules import RuleEngine
from log_analyzer.whitelist import WhitelistManager


@pytest.fixture
def make_worker(tmp_path, qapp):
    def create(path="unused.log"):
        return workers.LogAnalysisWorker(
            path, RuleEngine(), WhitelistManager(str(tmp_path / "whitelist.json")),
        )
    return create


def entries(count):
    for index in range(1, count + 1):
        yield SourceEntry(index, "10.0.0.42", "sqlmap", f"raw-{index}")


def capture(worker):
    batches, results, progress, order = [], [], [], []
    worker.findings_found.connect(lambda batch: (batches.append(batch), order.append("batch")))
    worker.completed.connect(lambda result: (results.append(result), order.append("complete")))
    worker.progress.connect(progress.append)
    return batches, results, progress, order


def test_batches_flush_before_completion(make_worker, monkeypatch):
    worker = make_worker()
    worker.BATCH_SIZE = 64
    monkeypatch.setattr(workers, "iter_entries", lambda *_args, **_kwargs: entries(150))
    batches, results, progress, order = capture(worker)
    worker.run()
    assert [len(batch) for batch in batches] == [64, 64, 22]
    assert order == ["batch", "batch", "batch", "complete"]
    result = results[0]
    assert len(result.findings) == 150
    assert result.processed_entries == 150
    assert result.ip_attack_count == Counter({"10.0.0.42": 150})
    assert progress[-1] == 100


def test_cancel_stops_input_and_flushes_partial_batch(make_worker, monkeypatch):
    worker = make_worker()
    consumed = []
    def stream(*_args, **_kwargs):
        for item in entries(100):
            consumed.append(item.line_no)
            if item.line_no == 8:
                worker.cancel()
            yield item
    monkeypatch.setattr(workers, "iter_entries", stream)
    batches, results, progress, _order = capture(worker)
    worker.run()
    assert consumed == list(range(1, 9))
    assert sum(map(len, batches)) == 7
    assert results[0].cancelled
    assert results[0].error is None
    assert results[0].processed_entries == 7
    assert 100 not in progress


def test_input_error_keeps_findings_and_does_not_emit_100(make_worker, monkeypatch):
    worker = make_worker()
    def broken(*_args, **_kwargs):
        yield from entries(4)
        raise OSError("read failed")
    monkeypatch.setattr(workers, "iter_entries", broken)
    batches, results, progress, _order = capture(worker)
    worker.run()
    assert sum(map(len, batches)) == 4
    assert len(results[0].findings) == 4
    assert "read failed" in results[0].error
    assert not results[0].cancelled
    assert 100 not in progress


def test_outer_exception_fallback_preserves_delivered_evidence(make_worker, monkeypatch):
    worker = make_worker()
    item = Finding(1, "10.0.0.42", 10, "Scanner", "sqlmap", "sqlmap", "evidence")
    class BrokenAnalyzer:
        def __init__(self, *_args):
            pass
        def analyze(self, _entries, **kwargs):
            kwargs["on_finding"](item)
            kwargs["on_progress"](1, 0, "processing")
            raise RuntimeError("unexpected integration failure")
    monkeypatch.setattr(workers, "LogAnalyzer", BrokenAnalyzer)
    monkeypatch.setattr(workers, "iter_entries", lambda *_args, **_kwargs: iter(()))
    batches, results, progress, _order = capture(worker)
    worker.run()
    assert batches == [[item]]
    assert results[0].findings == [item]
    assert results[0].processed_entries == 1
    assert results[0].ip_attack_count == {item.ip: 1}
    assert "integration failure" in results[0].error
    assert 100 not in progress


def test_byte_progress_is_monotone_and_completion_owns_100(make_worker, monkeypatch):
    worker = make_worker()
    def stream(_path, **kwargs):
        for current in (0, 25, 25, 70, 30, 100):
            kwargs["on_progress"](current, 100)
        yield from entries(1)
    monkeypatch.setattr(workers, "iter_entries", stream)
    _batches, results, progress, _order = capture(worker)
    worker.run()
    assert progress == [0, 25, 70, 99, 100]
    assert results[0].error is None


def test_empty_file_is_success_with_zero_counts(make_worker, tmp_path):
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    worker = make_worker(str(path))
    batches, results, progress, _order = capture(worker)
    worker.run()
    assert batches == []
    assert results[0].processed_entries == results[0].total_entries == 0
    assert not results[0].cancelled and not results[0].error
    assert progress == [0, 100]


def test_missing_file_is_failure_not_clean_result(make_worker, tmp_path):
    worker = make_worker(str(tmp_path / "missing.log"))
    _batches, results, progress, _order = capture(worker)
    worker.run()
    assert results[0].error
    assert 100 not in progress


def test_worker_uses_immutable_whitelist_snapshot(make_worker):
    worker = make_worker()
    original = worker.whitelist.copy()
    another = workers.LogAnalysisWorker("none.log", RuleEngine(), original)
    original.add_ip("10.0.0.42")
    original.add_suppressed_category("Scanner")
    assert not another.whitelist.is_ip_whitelisted("10.0.0.42")
    assert not another.whitelist.is_category_suppressed("Scanner")


def test_legacy_signals_remain_compatible(make_worker, monkeypatch):
    worker = make_worker()
    monkeypatch.setattr(workers, "iter_entries", lambda *_a, **_k: entries(3))
    individual, legacy = [], []
    worker.finding_found.connect(individual.append)
    worker.finished_analysis.connect(lambda items, counts: legacy.append((items, counts)))
    worker.run()
    assert legacy[0][0] == individual
    assert len(individual) == 3
    assert legacy[0][1] == {"10.0.0.42": 3}


def test_precancelled_geoip_does_not_construct_resolver(qapp, monkeypatch):
    monkeypatch.setattr(workers, "GeoIPResolver", lambda **_k: pytest.fail("cancelled"))
    worker = workers.GeoIPLookupWorker(["8.8.8.8"])
    outcomes, infos = [], []
    worker.finished_lookup.connect(lambda cancelled, error: outcomes.append((cancelled, error)))
    worker.resolved.connect(infos.extend)
    worker.cancel()
    worker.run()
    assert outcomes == [(True, "")]
    assert infos == []


def test_geoip_deduplicates_and_cancel_closes_reader(qapp, monkeypatch):
    calls, closed, outcomes, infos = [], [], [], []
    worker = workers.GeoIPLookupWorker(["8.8.8.8", "8.8.8.8", "1.1.1.1"])
    class Resolver:
        def __init__(self, **_kwargs):
            pass
        def lookup(self, ip):
            calls.append(ip)
            worker.cancel()
            return GeoInfo(ip, country="US")
        def close(self):
            closed.append(True)
    monkeypatch.setattr(workers, "GeoIPResolver", Resolver)
    worker.resolved.connect(infos.extend)
    worker.finished_lookup.connect(lambda cancelled, error: outcomes.append((cancelled, error)))
    worker.run()
    assert calls == ["8.8.8.8"]
    assert len(infos) == 1
    assert closed == [True]
    assert outcomes == [(True, "")]


@pytest.mark.parametrize("fail_at", ["init", "lookup", "close"])
def test_geoip_failure_always_emits_terminal_signal(qapp, monkeypatch, fail_at):
    outcomes = []
    class Resolver:
        def __init__(self, **_kwargs):
            if fail_at == "init":
                raise RuntimeError("init failed")
        def lookup(self, ip):
            if fail_at == "lookup":
                raise RuntimeError("lookup failed")
            return GeoInfo(ip)
        def close(self):
            if fail_at == "close":
                raise RuntimeError("close failed")
    monkeypatch.setattr(workers, "GeoIPResolver", Resolver)
    worker = workers.GeoIPLookupWorker(["8.8.8.8"])
    worker.finished_lookup.connect(lambda cancelled, error: outcomes.append((cancelled, error)))
    worker.run()
    assert outcomes == [(False, f"{fail_at} failed")]
