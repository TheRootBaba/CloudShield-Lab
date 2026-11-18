from __future__ import annotations

from collections import defaultdict
from typing import Iterable


class AttackGraph:
    def __init__(self) -> None:
        self._adjacency: dict[str, set[str]] = defaultdict(set)

    def add_edge(self, source: str, target: str) -> None:
        if source:
            self._adjacency[str(source)].add(str(target))
        if target:
            self._adjacency[str(target)]

    def neighbors(self, node: str) -> list[str]:
        return sorted(self._adjacency.get(str(node), set()))

    def nodes(self) -> list[str]:
        return sorted(self._adjacency)


def build_attack_graph(relationships: Iterable[dict[str, str]] | dict[str, Iterable[str]]) -> AttackGraph:
    graph = AttackGraph()
    if isinstance(relationships, dict):
        for source, targets in relationships.items():
            if isinstance(targets, (list, tuple, set)):
                for target in targets:
                    graph.add_edge(str(source), str(target))
        return graph
    for relationship in relationships if isinstance(relationships, (list, tuple)) else []:
        if not isinstance(relationship, dict):
            continue
        source = relationship.get("source") or relationship.get("from")
        target = relationship.get("target") or relationship.get("to")
        if source is not None and target is not None:
            graph.add_edge(str(source), str(target))
    return graph


def find_attack_paths(graph: AttackGraph, source: str, target: str) -> list[list[str]]:
    if not graph.nodes():
        return []
    source, target = str(source), str(target)
    if source not in graph.nodes() or target not in graph.nodes():
        return []
    paths: list[list[str]] = []

    def visit(node: str, seen: set[str], path: list[str]) -> None:
        if node == target:
            paths.append(path.copy())
            return
        for neighbor in graph.neighbors(node):
            if neighbor not in seen:
                visit(neighbor, seen | {neighbor}, path + [neighbor])

    visit(source, {source}, [source])
    return sorted(paths, key=lambda path: (len(path), path))
