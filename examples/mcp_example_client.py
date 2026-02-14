"""Run from the repository root:
uv run python examples/mcp_example_client.py

Example showing how to use MCP_ToolExecutor with HTTP-based MCP server.
"""

import asyncio

from mcp_pvp import create_mcp_executor_http


async def main():
    # Connect to HTTP MCP server and create executor
    async with create_mcp_executor_http("http://localhost:8002/mcp") as executor:
        # The executor's session is already initialized
        # Access the underlying session to list tools

        # List available tools
        tools = await executor.list_tools()
        print(f"Available tools: {list(tools)}")
        tool_info = await executor.get_tool_info(tools[0]) if tools else None
        print(f"Tool info for {tools[0]}: {tool_info}" if tool_info else "No tools available")
        tool = await executor.get_tool(tools[0]) if tools else None
        print(f"Tool details: {tool}" if tool else "No tool details available")

        # Execute tool via the executor
        result = await executor.execute(tool_name=tools[0], injected_args={"a": 5, "b": 7})

        print(f"Result: {result}")


if __name__ == "__main__":
    asyncio.run(main())
