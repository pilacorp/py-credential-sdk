from __future__ import annotations

from typing import Any, Callable, TypeVar

from credential.common.dto.proof import Proof

T = TypeVar("T")
U = TypeVar("U")


def serialize_types(types: list[str]) -> Any:
    if not types:
        return None
    if len(types) == 1:
        return types[0]
    return list(types)


def map_slice(items: list[T], fn: Callable[[T], U]) -> list[U]:
    return [fn(x) for x in items]


def serialize_contexts(contexts: list[Any]) -> list[Any]:
    validated: list[Any] = []
    for i, ctx in enumerate(contexts):
        if ctx is None:
            raise ValueError(f"failed to validate context: context entry at index {i} is nil")
        if isinstance(ctx, str):
            if not ctx:
                raise ValueError(f"failed to validate context: context string at index {i} is empty")
            validated.append(ctx)
        elif isinstance(ctx, dict):
            if "@context" in ctx:
                raise ValueError(
                    f"failed to validate context: context object at index {i} must not contain nested @context"
                )
            validated.append(ctx)
        else:
            raise ValueError(
                f"failed to validate context: invalid context entry at index {i}: must be string or map, got {type(ctx)}"
            )
    return validated


def serialize_proofs(proofs: list[Proof]) -> Any:
    if not proofs:
        return None
    result = [p.to_map() for p in proofs]
    if len(result) == 1:
        return result[0]
    return result
