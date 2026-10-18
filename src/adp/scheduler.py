"""Dependency graph helpers used before dispatch and for diagnostics."""


def order(dependencies: dict[int, list[int]], priorities: dict[int, int] | None = None) -> list[int]:
    priorities = priorities or {}
    indegree = {node: 0 for node in dependencies}
    children: dict[int, list[int]] = {node: [] for node in dependencies}
    for node, parents in dependencies.items():
        for parent in parents:
            if parent not in dependencies:
                continue
            indegree[node] += 1
            children[parent].append(node)
    ready = sorted((n for n, d in indegree.items() if d == 0), key=lambda n: (-priorities.get(n, 0), n))
    output = []
    while ready:
        node = ready.pop(0)
        output.append(node)
        for child in children[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
        ready.sort(key=lambda n: (-priorities.get(n, 0), n))
    if len(output) != len(dependencies):
        raise ValueError("Ticket dependency cycle")
    return output

