from examples.mock_demo import run_demo


def test_full_offline_demo_runs_end_to_end():
    """Exercises the real code paths described in README's quickstart:
    allow, trifecta-block, signed agent message, tamper detection."""
    assert run_demo() == 0
