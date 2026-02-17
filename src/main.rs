use anyhow::Result;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use tracing_subscriber::EnvFilter;

const H1_API: &str = "https://api.hackerone.com/v1";

// ── Tool input types ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetReportInput {
    #[schemars(description = "The numeric report ID")]
    pub id: u64,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListReportsInput {
    #[schemars(description = "Filter by program handle, e.g. \"example_team\" (optional)")]
    pub program: Option<String>,
    #[schemars(
        description = "Filter by state: new | triaged | needs-more-info | resolved | \
                        not-applicable | informative | duplicate | spam | retesting (optional)"
    )]
    pub state: Option<String>,
    #[schemars(description = "Page number (default: 1)")]
    pub page: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddCommentInput {
    #[schemars(description = "The numeric report ID")]
    pub report_id: u64,
    #[schemars(description = "Comment body – Markdown is supported")]
    pub message: String,
    #[schemars(description = "true → internal team-only comment; false (default) → public")]
    pub internal: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ChangeStateInput {
    #[schemars(description = "The numeric report ID")]
    pub report_id: u64,
    #[schemars(
        description = "Target state: resolved | not-applicable | informative | \
                        duplicate | spam | needs-more-info"
    )]
    pub state: String,
    #[schemars(description = "Optional message to accompany the state change")]
    pub message: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListProgramsInput {
    #[schemars(description = "Page number (default: 1)")]
    pub page: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetProgramInput {
    #[schemars(description = "Program handle, e.g. \"example_team\"")]
    pub handle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetUserInput {
    #[schemars(description = "HackerOne username, e.g. \"spoorga\"")]
    pub username: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AwardBountyInput {
    #[schemars(description = "The numeric report ID")]
    pub report_id: u64,
    #[schemars(description = "Bounty amount in USD as a string, e.g. \"500.00\"")]
    pub amount: String,
    #[schemars(description = "Optional bonus amount in USD as a string, e.g. \"100.00\"")]
    pub bonus_amount: Option<String>,
    #[schemars(description = "Optional message for the reporter")]
    pub message: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetActivitiesInput {
    #[schemars(description = "HackerOne program handle, e.g. \"example_team\"")]
    pub handle: String,
    #[schemars(description = "Page number (default: 1)")]
    pub page: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchReportsInput {
    #[schemars(description = "Full-text search keyword")]
    pub keyword: String,
    #[schemars(description = "Page number (default: 1)")]
    pub page: Option<u32>,
}

// ── Server struct ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HackerOneMcp {
    client: reqwest::Client,
    username: String,
    token: String,
    tool_router: ToolRouter<HackerOneMcp>,
}

// Private helpers — separate impl block so the #[tool_router] macro only sees
// the tool methods below.
impl HackerOneMcp {
    async fn h1_get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{H1_API}{path}");
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.token))
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    async fn h1_post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{H1_API}{path}");
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.token))
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    async fn h1_patch(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{H1_API}{path}");
        let resp = self
            .client
            .patch(&url)
            .basic_auth(&self.username, Some(&self.token))
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    fn pretty(val: serde_json::Value) -> String {
        serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string())
    }
}

// ── Tool registrations ────────────────────────────────────────────────────────

#[tool_router]
impl HackerOneMcp {
    pub fn new(username: String, token: String) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("hackerone-mcp/0.1.0")
            .build()
            .expect("Failed to build reqwest client");
        Self {
            client,
            username,
            token,
            tool_router: Self::tool_router(),
        }
    }

    /// Return current authenticated user info.
    #[tool(description = "Get information about the authenticated HackerOne user (me endpoint)")]
    async fn get_me(&self) -> String {
        match self.h1_get("/me").await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Get a HackerOne user by username.
    #[tool(description = "Get the profile of a specific HackerOne user by username")]
    async fn get_user(&self, Parameters(p): Parameters<GetUserInput>) -> String {
        match self.h1_get(&format!("/users/{}", p.username)).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error fetching user '{}': {e}", p.username),
        }
    }

    /// List reports with optional program/state filters.
    #[tool(
        description = "List vulnerability reports. Optionally filter by program handle and/or \
                        report state (new, triaged, needs-more-info, resolved, not-applicable, \
                        informative, duplicate, spam, retesting)."
    )]
    async fn list_reports(&self, Parameters(p): Parameters<ListReportsInput>) -> String {
        let mut path = format!("/reports?page[number]={}", p.page.unwrap_or(1));
        if let Some(prog) = &p.program {
            path.push_str(&format!("&filter[program][]={prog}"));
        }
        if let Some(state) = &p.state {
            path.push_str(&format!("&filter[state][]={state}"));
        }
        match self.h1_get(&path).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error listing reports: {e}"),
        }
    }

    /// Get one report by ID.
    #[tool(description = "Get the full details of a specific vulnerability report by its numeric ID")]
    async fn get_report(&self, Parameters(p): Parameters<GetReportInput>) -> String {
        match self.h1_get(&format!("/reports/{}", p.id)).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error fetching report {}: {e}", p.id),
        }
    }

    /// Add a comment to a report.
    #[tool(
        description = "Add a comment to a report. Set internal=true for a private team-only \
                        comment (not visible to the reporter)."
    )]
    async fn add_comment(&self, Parameters(p): Parameters<AddCommentInput>) -> String {
        let body = serde_json::json!({
            "data": {
                "type": "comment",
                "attributes": {
                    "message": p.message,
                    "internal": p.internal.unwrap_or(false),
                }
            }
        });
        match self
            .h1_post(&format!("/reports/{}/comments", p.report_id), body)
            .await
        {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error adding comment: {e}"),
        }
    }

    /// Change a report's state.
    #[tool(
        description = "Change the state of a report. Valid target states: resolved, \
                        not-applicable, informative, duplicate, spam, needs-more-info. \
                        An optional message can be left for the reporter."
    )]
    async fn change_report_state(&self, Parameters(p): Parameters<ChangeStateInput>) -> String {
        let valid = [
            "resolved",
            "not-applicable",
            "informative",
            "duplicate",
            "spam",
            "needs-more-info",
            "triaged",
            "new",
        ];
        if !valid.contains(&p.state.as_str()) {
            return format!(
                "Unknown state '{}'. Valid: resolved, not-applicable, informative, \
                 duplicate, spam, needs-more-info",
                p.state
            );
        }
        let body = serde_json::json!({
            "data": {
                "type": "report",
                "attributes": { "state": p.state },
            }
        });
        match self
            .h1_patch(&format!("/reports/{}/state", p.report_id), body)
            .await
        {
            Err(e) => format!("Error changing state: {e}"),
            Ok(v) => {
                // If a message was provided, post it as a follow-up comment.
                if let Some(msg) = &p.message {
                    let comment_body = serde_json::json!({
                        "data": {
                            "type": "comment",
                            "attributes": { "message": msg, "internal": false },
                        }
                    });
                    let _ = self
                        .h1_post(&format!("/reports/{}/comments", p.report_id), comment_body)
                        .await;
                }
                Self::pretty(v)
            }
        }
    }

    /// List programs.
    #[tool(description = "List HackerOne programs you are a member of or have access to")]
    async fn list_programs(&self, Parameters(p): Parameters<ListProgramsInput>) -> String {
        let path = format!("/programs?page[number]={}", p.page.unwrap_or(1));
        match self.h1_get(&path).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error listing programs: {e}"),
        }
    }

    /// Get one program by handle.
    #[tool(description = "Get the details of a specific HackerOne program by its handle")]
    async fn get_program(&self, Parameters(p): Parameters<GetProgramInput>) -> String {
        match self.h1_get(&format!("/programs/{}", p.handle)).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error fetching program '{}': {e}", p.handle),
        }
    }

    /// Award a bounty.
    #[tool(
        description = "Award a bounty to a report. Provide report_id, the USD amount as a \
                        string (e.g. \"500.00\"), an optional bonus, and an optional message."
    )]
    async fn award_bounty(&self, Parameters(p): Parameters<AwardBountyInput>) -> String {
        let mut attrs = serde_json::json!({ "amount": p.amount });
        if let Some(bonus) = &p.bonus_amount {
            attrs["bonus"] = serde_json::json!(bonus);
        }
        if let Some(msg) = &p.message {
            attrs["message"] = serde_json::json!(msg);
        }
        let body = serde_json::json!({
            "data": {
                "type": "bounty",
                "attributes": attrs,
            }
        });
        match self
            .h1_post(&format!("/reports/{}/bounty", p.report_id), body)
            .await
        {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error awarding bounty: {e}"),
        }
    }

    /// Get activities.
    #[tool(
        description = "Get recent activities for a HackerOne program. Requires the program handle."
    )]
    async fn get_activities(&self, Parameters(p): Parameters<GetActivitiesInput>) -> String {
        let path = format!(
            "/incremental/activities?handle={}&page[number]={}",
            urlencoding_simple(&p.handle),
            p.page.unwrap_or(1)
        );
        match self.h1_get(&path).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error fetching activities: {e}"),
        }
    }

    /// Search reports by keyword.
    #[tool(description = "Search reports by a keyword across all accessible programs")]
    async fn search_reports(&self, Parameters(p): Parameters<SearchReportsInput>) -> String {
        let path = format!(
            "/reports?page[number]={}&filter[keyword]={}",
            p.page.unwrap_or(1),
            urlencoding_simple(&p.keyword)
        );
        match self.h1_get(&path).await {
            Ok(v) => Self::pretty(v),
            Err(e) => format!("Error searching reports: {e}"),
        }
    }
}

// ── ServerHandler ─────────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for HackerOneMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "HackerOne MCP server. Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN \
                 environment variables before starting. Available tools: get_me, get_user, \
                 list_reports, get_report, add_comment, change_report_state, list_programs, \
                 get_program, award_bounty, get_activities, search_reports."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal percent-encoding for query-string values (no external crate needed).
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                out.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
            }
        }
    }
    out
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // IMPORTANT: all logging must go to stderr — stdout is the MCP JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("h1_mcp=info".parse().unwrap()),
        )
        .init();

    let username = std::env::var("HACKERONE_API_USERNAME")
        .expect("HACKERONE_API_USERNAME environment variable is not set");
    let token = std::env::var("HACKERONE_API_TOKEN")
        .expect("HACKERONE_API_TOKEN environment variable is not set");

    tracing::info!("HackerOne MCP server starting (api_user={})", username);

    let service = HackerOneMcp::new(username, token)
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("Server error: {e:?}"))?;

    service.waiting().await?;
    Ok(())
}
