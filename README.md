# h1-mcp

A [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for the [HackerOne API](https://api.hackerone.com/), written in Rust.

Exposes HackerOne operations as MCP tools so any MCP-compatible client (Claude Desktop, Claude Code, etc.) can interact with your HackerOne program directly.

## Tools

| Tool | Description |
|------|-------------|
| `get_me` | Get the authenticated user's profile |
| `get_user` | Look up any HackerOne user by username |
| `list_reports` | List reports, with optional program/state filters and pagination |
| `get_report` | Fetch full details of a report by numeric ID |
| `add_comment` | Add a public or internal comment to a report |
| `change_report_state` | Transition a report to a new state (resolved, triaged, etc.) |
| `list_programs` | List programs you have access to |
| `get_program` | Fetch details of a program by handle |
| `award_bounty` | Award a bounty (and optional bonus) to a report |
| `get_activities` | Fetch recent activity feed for a program |
| `search_reports` | Full-text search across reports |

## Prerequisites

- Rust (edition 2024)
- A HackerOne API token — generate one at **Settings → API Token**

## Build

```sh
cargo build --release
# binary: target/release/h1-mcp
```

## Usage

Set the two required environment variables and run the binary:

```sh
export HACKERONE_API_USERNAME=your_username
export HACKERONE_API_TOKEN=your_api_token
./target/release/h1-mcp
```

The server communicates over stdio using the MCP JSON-RPC protocol. All log output goes to stderr.

## Claude Desktop Configuration

Add the following to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hackerone": {
      "command": "/path/to/h1-mcp",
      "env": {
        "HACKERONE_API_USERNAME": "your_username",
        "HACKERONE_API_TOKEN": "your_api_token"
      }
    }
  }
}
```

## Claude Code Configuration

Add the server via the CLI:

```sh
claude mcp add hackerone /path/to/h1-mcp \
  -e HACKERONE_API_USERNAME=your_username \
  -e HACKERONE_API_TOKEN=your_api_token
```

## Dependencies

- [`rmcp`](https://crates.io/crates/rmcp) 0.16 — MCP server framework
- [`reqwest`](https://crates.io/crates/reqwest) 0.12 — HTTP client
- [`tokio`](https://crates.io/crates/tokio) — async runtime
- [`serde`](https://crates.io/crates/serde) / [`serde_json`](https://crates.io/crates/serde_json) — JSON serialization
