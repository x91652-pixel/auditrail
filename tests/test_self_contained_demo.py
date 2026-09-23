from auditrail._demo import run_demo


def test_self_contained_demo_runs_end_to_end():
    """This is what `auditrail demo` runs -- it must work with no repo
    checkout present, since it ships inside the installed package."""
    assert run_demo() == 0
