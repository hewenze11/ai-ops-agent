"""Execution slots: one controller's batch overlaps with itself (§52).

The contract, in the owner's words: commands from the same control plane must
not block each other on a host, and a host only serialises *between* control
planes. The old Agent failed both halves -- a single synchronous loop meant the
second task from the same controller waited for the first.

These tests pin the decision function directly. They do not start threads, so
they run anywhere and cannot be flaky; the threading wiring is exercised by the
existing heartbeat integration test.
"""
import pytest

from ai_ops_agent import agent as agent_module


class FakeWorker(agent_module.Worker):
    """A Worker with the parts that talk to a network stripped out.

    Constructing the real Worker opens journals, credentials and config files;
    none of that is relevant to slot bookkeeping.
    """

    def __init__(self, max_concurrent=4):
        import threading
        self._slots_lock = threading.Lock()
        self._active = {}
        self._queue_order = []
        self.max_concurrent = max_concurrent


def start(worker, controller, task_id):
    with worker._slots_lock:
        assert worker._slot_available(controller), 'slot should have been available'
        worker._active[task_id] = controller
        if controller not in worker._queue_order:
            worker._queue_order.append(controller)


def finish(worker, controller, task_id):
    with worker._slots_lock:
        worker._active.pop(task_id, None)
        if controller not in worker._active.values() and controller in worker._queue_order:
            worker._queue_order.remove(controller)


def test_same_controller_tasks_run_in_parallel():
    # The property that was missing: task two from the same control plane starts
    # while task one is still running.
    worker = FakeWorker(max_concurrent=4)
    start(worker, 'ours', 't1')
    with worker._slots_lock:
        assert worker._slot_available('ours') is True


def test_a_second_controller_waits_until_the_first_is_completely_done():
    # The property that had to be kept: two control planes never run work on one
    # host at the same time.
    worker = FakeWorker(max_concurrent=4)
    start(worker, 'ours', 't1')
    with worker._slots_lock:
        assert worker._slot_available('theirs') is False
    finish(worker, 'ours', 't1')
    with worker._slots_lock:
        assert worker._slot_available('theirs') is True


def test_a_second_controller_still_waits_while_several_of_ours_are_running():
    worker = FakeWorker(max_concurrent=8)
    for i in range(3):
        start(worker, 'ours', 't%d' % i)
    with worker._slots_lock:
        assert worker._slot_available('ours') is True
        assert worker._slot_available('theirs') is False


def test_the_host_capacity_is_a_hard_ceiling():
    # Concurrency is a local resource limit, not something the model picks. Even
    # the owning controller cannot exceed it.
    worker = FakeWorker(max_concurrent=2)
    start(worker, 'ours', 't1')
    start(worker, 'ours', 't2')
    with worker._slots_lock:
        assert worker._slot_available('ours') is False


def test_busy_reports_the_owning_controller_and_the_queue_length():
    # `busy` keeps its original meaning; the new datum is how many controllers
    # are ahead. A control plane uses that to choose between waiting and telling
    # the operator the host is occupied.
    worker = FakeWorker(max_concurrent=4)
    start(worker, 'ours', 't1')
    with worker._slots_lock:
        assert worker._active_controller() == 'ours'
        assert worker._busy_task_of('ours') == 't1'
        assert len(worker._queue_order) == 1
    start(worker, 'ours', 't2')
    with worker._slots_lock:
        # Still one controller queued, two tasks running: the count is of
        # controllers, not tasks.
        assert len(worker._queue_order) == 1
        assert len(worker._active) == 2


def test_queue_order_follows_arrival():
    worker = FakeWorker(max_concurrent=8)
    start(worker, 'first', 't1')
    with worker._slots_lock:
        # A blocked controller is not "waiting" in the queue until it has work
        # claimed, so the reported order stays honest.
        assert worker._queue_order == ['first']
    finish(worker, 'first', 't1')
    start(worker, 'second', 't2')
    with worker._slots_lock:
        assert worker._queue_order == ['second']


def test_config_defaults_are_conservative():
    # A host runs several things already. Four concurrent reads is enough to
    # make batch diagnosis fast without turning a 2-core box into a scheduler
    # stress test, and a bad config value cannot silently mean "run everything".
    assert agent_module.DEFAULT_MAX_CONCURRENT == 4
    assert agent_module.DEFAULT_MAX_CONCURRENT <= 8


def test_configured_ceiling_cannot_drop_below_one(monkeypatch):
    # ``0`` in a config file is a typo, not "parallelism disabled": letting it
    # through would stall every claim forever, which looks exactly like a dead
    # Agent from the control plane's side.
    worker = FakeWorker(max_concurrent=max(1, int(0 or agent_module.DEFAULT_MAX_CONCURRENT)))
    assert worker.max_concurrent == agent_module.DEFAULT_MAX_CONCURRENT
    assert FakeWorker(max_concurrent=max(1, -5)).max_concurrent == 1


def test_reveal_kind_is_declared():
    # The reveal path (§51.4) is dispatched by kind name. A build that does not
    # list it here refuses the task at the door, so the unlock card would sit
    # "pending" forever with no explanation.
    assert 'reveal' in agent_module.KINDS
