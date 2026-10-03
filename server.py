"""MCP entrypoint. stdio transport only. stdout is protocol-only: NO print().

Tools:
  - secure_search(query, engine="google", num_results=10)
  - search_status()
  - benchmark_run(dataset="core")
"""
# TODO: [VERIFY] import path/server class for the installed mcp SDK version.


def secure_search(query: str, engine: str = "google", num_results: int = 10) -> dict:
    """Fetch -> normalize -> detect -> verdict -> label -> slim -> budget -> audit."""
    raise NotImplementedError


def search_status() -> dict:
    """Budget usage, cache stats, last-N verdict summary (no content)."""
    raise NotImplementedError


def benchmark_run(dataset: str = "core") -> dict:
    """Run bundled fixtures and return metrics."""
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
