"""MCP entrypoint. stdio transport only. stdout is protocol-only: NO print().

Tools:
  - secure_search(query, engine="google", num_results=10)
  - search_status()
  - benchmark_run(dataset="core")
"""

import json
import logging
import os
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from serpshield.budget import Budget, Cache
from serpshield.config import get_config
from serpshield.pipeline import run_pipeline


# Load .env from project root if it exists
if load_dotenv:
    project_root = Path(__file__).parent
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path)

# Configure logging to stderr only
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Module-level singletons
config = get_config()
CACHE = Cache(ttl_seconds=config.budget.cache_ttl_seconds)
BUDGET = Budget(config=config)

# Keep last N search summaries (no content)
RECENT_SEARCHES = deque(maxlen=20)


async def _tool_secure_search(args: dict):
    """Execute secure_search tool."""
    try:
        query = args.get("query", "")
        engine = args.get("engine", "google")
        num_results = args.get("num_results", 10)
        
        result = run_pipeline(
            query=query,
            engine=engine,
            num_results=num_results,
            cache=CACHE,
            budget=BUDGET
        )
        
        # Add summary to recent searches (counts only, no content)
        if "error" not in result:
            summary = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "engine": engine,
                "mode": result["meta"]["mode"],
                "blocked": result["meta"]["blocked_count"],
                "flagged": result["meta"]["flagged_count"],
                "suspicious": result["meta"]["suspicious_count"],
            }
            RECENT_SEARCHES.append(summary)
        
        return [{"type": "text", "text": json.dumps(result)}]
    except Exception as e:
        logger.error(f"secure_search failed: {type(e).__name__}")
        return [{"type": "text", "text": '{"error": "internal error"}'}]


async def _tool_search_status(args: dict):
    """Execute search_status tool."""
    try:
        mode = os.environ.get("SERPSHIELD_MODE", "live").strip().lower()
        
        status = {
            "budget": BUDGET.status(),
            "cache": CACHE.stats(),
            "mode": mode,
            "recent_searches": list(RECENT_SEARCHES)
        }
        
        return [{"type": "text", "text": json.dumps(status)}]
    except Exception as e:
        logger.error(f"search_status failed: {type(e).__name__}")
        return [{"type": "text", "text": '{"error": "internal error"}'}]


async def _tool_benchmark_run(args: dict):
    """Execute benchmark_run tool."""
    try:
        dataset = args.get("dataset", "core")
        
        if dataset not in ["core", "heldout"]:
            return [{"type": "text", "text": '{"error": "invalid dataset"}'}]
        
        # Try to import and run the benchmark
        try:
            from benchmark.run_benchmark import run
            result = run(dataset)
            return [{"type": "text", "text": json.dumps(result)}]
        except (ImportError, AttributeError):
            return [{"type": "text", "text": '{"error": "benchmark not available yet"}'}]
    except Exception as e:
        logger.error(f"benchmark_run failed: {type(e).__name__}")
        return [{"type": "text", "text": '{"error": "internal error"}'}]


async def main():
    """Run the MCP server on stdio."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp import types
        
        server = Server("serpshield")
        
        # Register tools using request handlers
        async def handle_list_tools(ctx, request):
            return types.ListToolsResult(
                tools=[
                    types.Tool(
                        name="secure_search",
                        description="Search with automatic prompt injection protection",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "query": {"type": "string", "description": "Search query"},
                                "engine": {
                                    "type": "string",
                                    "enum": ["google", "google_news"],
                                    "default": "google",
                                    "description": "Search engine"
                                },
                                "num_results": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 10,
                                    "default": 10,
                                    "description": "Number of results to return"
                                }
                            },
                            "required": ["query"]
                        }
                    ),
                    types.Tool(
                        name="search_status",
                        description="Get budget, cache stats, and recent search summary",
                        inputSchema={
                            "type": "object",
                            "properties": {}
                        }
                    ),
                    types.Tool(
                        name="benchmark_run",
                        description="Run benchmark test suite",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "dataset": {
                                    "type": "string",
                                    "enum": ["core", "heldout"],
                                    "default": "core",
                                    "description": "Which dataset to run"
                                }
                            }
                        }
                    )
                ]
            )
        
        async def handle_call_tool(ctx, request):
            if request.name == "secure_search":
                content = await _tool_secure_search(request.arguments)
            elif request.name == "search_status":
                content = await _tool_search_status(request.arguments)
            elif request.name == "benchmark_run":
                content = await _tool_benchmark_run(request.arguments)
            else:
                content = [{"type": "text", "text": f'{{"error": "Unknown tool: {request.name}"}}'}]
            
            return types.CallToolResult(content=[types.TextContent(**c) for c in content])
        
        server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
        server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    except ImportError:
        logger.error("MCP server module not available")
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
