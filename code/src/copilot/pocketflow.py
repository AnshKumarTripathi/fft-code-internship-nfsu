"""Vendored Pocket Flow core (zero deps) — https://github.com/The-Pocket/PocketFlow

Pinned for Phase 96 copilot orchestration only. Do not wrap detectors / STAGE_ORDER.
"""

from __future__ import annotations

import asyncio
import copy
import time
import warnings


class BaseNode:
    def __init__(self) -> None:
        self.params: dict = {}
        self.successors: dict = {}

    def set_params(self, params: dict) -> None:
        self.params = params

    def next(self, node: "BaseNode", action: str = "default") -> "BaseNode":
        if action in self.successors:
            warnings.warn(f"Overwriting successor for action '{action}'")
        self.successors[action] = node
        return node

    def prep(self, shared):  # noqa: ANN001
        pass

    def exec(self, prep_res):  # noqa: ANN001
        pass

    def post(self, shared, prep_res, exec_res):  # noqa: ANN001
        pass

    def _exec(self, prep_res):  # noqa: ANN001
        return self.exec(prep_res)

    def _run(self, shared):  # noqa: ANN001
        prep_res = self.prep(shared)
        exec_res = self._exec(prep_res)
        return self.post(shared, prep_res, exec_res)

    def run(self, shared):  # noqa: ANN001
        if self.successors:
            warnings.warn("Node won't run successors. Use Flow.")
        return self._run(shared)

    def __rshift__(self, other: "BaseNode") -> "BaseNode":
        return self.next(other)

    def __sub__(self, action: str) -> "_ConditionalTransition":
        if isinstance(action, str):
            return _ConditionalTransition(self, action)
        raise TypeError("Action must be a string")


class _ConditionalTransition:
    def __init__(self, src: BaseNode, action: str) -> None:
        self.src = src
        self.action = action

    def __rshift__(self, tgt: BaseNode) -> BaseNode:
        return self.src.next(tgt, self.action)


class Node(BaseNode):
    def __init__(self, max_retries: int = 1, wait: float = 0) -> None:
        super().__init__()
        self.max_retries = max_retries
        self.wait = wait
        self.cur_retry = 0

    def exec_fallback(self, prep_res, exc):  # noqa: ANN001
        raise exc

    def _exec(self, prep_res):  # noqa: ANN001
        for self.cur_retry in range(self.max_retries):
            try:
                return self.exec(prep_res)
            except Exception as exc:
                if self.cur_retry == self.max_retries - 1:
                    return self.exec_fallback(prep_res, exc)
                if self.wait > 0:
                    time.sleep(self.wait)
        return None


class BatchNode(Node):
    def _exec(self, items):  # noqa: ANN001
        return [super(BatchNode, self)._exec(item) for item in (items or [])]


class Flow(BaseNode):
    def __init__(self, start: BaseNode | None = None) -> None:
        super().__init__()
        self.start_node = start

    def start(self, start: BaseNode) -> BaseNode:
        self.start_node = start
        return start

    def get_next_node(self, curr: BaseNode, action: str | None) -> BaseNode | None:
        nxt = curr.successors.get(action or "default")
        if not nxt and curr.successors:
            warnings.warn(
                f"Flow ends: '{action}' not found in {list(curr.successors)}"
            )
        return nxt

    def _orch(self, shared, params=None):  # noqa: ANN001
        curr = copy.copy(self.start_node)
        merged = params or {**self.params}
        last_action = None
        while curr:
            curr.set_params(merged)
            last_action = curr._run(shared)
            curr = copy.copy(self.get_next_node(curr, last_action))
        return last_action

    def _run(self, shared):  # noqa: ANN001
        prep_res = self.prep(shared)
        orch_res = self._orch(shared)
        return self.post(shared, prep_res, orch_res)

    def post(self, shared, prep_res, exec_res):  # noqa: ANN001
        return exec_res


class BatchFlow(Flow):
    def _run(self, shared):  # noqa: ANN001
        prep_res = self.prep(shared) or []
        for batch_params in prep_res:
            self._orch(shared, {**self.params, **batch_params})
        return self.post(shared, prep_res, None)


class AsyncNode(Node):
    async def prep_async(self, shared):  # noqa: ANN001
        pass

    async def exec_async(self, prep_res):  # noqa: ANN001
        pass

    async def exec_fallback_async(self, prep_res, exc):  # noqa: ANN001
        raise exc

    async def post_async(self, shared, prep_res, exec_res):  # noqa: ANN001
        pass

    async def _exec(self, prep_res):  # noqa: ANN001
        for self.cur_retry in range(self.max_retries):
            try:
                return await self.exec_async(prep_res)
            except Exception as exc:
                if self.cur_retry == self.max_retries - 1:
                    return await self.exec_fallback_async(prep_res, exc)
                if self.wait > 0:
                    await asyncio.sleep(self.wait)
        return None

    async def run_async(self, shared):  # noqa: ANN001
        if self.successors:
            warnings.warn("Node won't run successors. Use AsyncFlow.")
        return await self._run_async(shared)

    async def _run_async(self, shared):  # noqa: ANN001
        prep_res = await self.prep_async(shared)
        exec_res = await self._exec(prep_res)
        return await self.post_async(shared, prep_res, exec_res)

    def _run(self, shared):  # noqa: ANN001
        raise RuntimeError("Use run_async.")


class AsyncBatchNode(AsyncNode, BatchNode):
    async def _exec(self, items):  # noqa: ANN001
        return [await super(AsyncBatchNode, self)._exec(item) for item in items]


class AsyncParallelBatchNode(AsyncNode, BatchNode):
    async def _exec(self, items):  # noqa: ANN001
        return await asyncio.gather(
            *(super(AsyncParallelBatchNode, self)._exec(item) for item in items)
        )


class AsyncFlow(Flow, AsyncNode):
    async def _orch_async(self, shared, params=None):  # noqa: ANN001
        curr = copy.copy(self.start_node)
        merged = params or {**self.params}
        last_action = None
        while curr:
            curr.set_params(merged)
            if isinstance(curr, AsyncNode):
                last_action = await curr._run_async(shared)
            else:
                last_action = curr._run(shared)
            curr = copy.copy(self.get_next_node(curr, last_action))
        return last_action

    async def _run_async(self, shared):  # noqa: ANN001
        prep_res = await self.prep_async(shared)
        orch_res = await self._orch_async(shared)
        return await self.post_async(shared, prep_res, orch_res)

    async def post_async(self, shared, prep_res, exec_res):  # noqa: ANN001
        return exec_res


class AsyncBatchFlow(AsyncFlow, BatchFlow):
    async def _run_async(self, shared):  # noqa: ANN001
        prep_res = await self.prep_async(shared) or []
        for batch_params in prep_res:
            await self._orch_async(shared, {**self.params, **batch_params})
        return await self.post_async(shared, prep_res, None)


class AsyncParallelBatchFlow(AsyncFlow, BatchFlow):
    async def _run_async(self, shared):  # noqa: ANN001
        prep_res = await self.prep_async(shared) or []
        await asyncio.gather(
            *(
                self._orch_async(shared, {**self.params, **batch_params})
                for batch_params in prep_res
            )
        )
        return await self.post_async(shared, prep_res, None)
