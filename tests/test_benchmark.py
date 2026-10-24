from tools import benchmark


def test_benchmark_one_run_in_process(capsys):
    assert benchmark.main(["--runs", "1", "--no-write"]) == 0  # 0 = attack incident formed correctly
    out = capsys.readouterr().out
    assert '"attack_correct": true' in out and '"incidents": 5' in out and '"suppressed": 22' in out


def test_render_lists_every_run():
    runs = [{"alerts": 50, "total_ms": 1.0}, {"alerts": 50, "total_ms": 2.0}]
    md = benchmark.render(runs, "test")
    assert "| Metric | Run 1 | Run 2 |" in md and "| `total_ms` | 1.0 | 2.0 |" in md
