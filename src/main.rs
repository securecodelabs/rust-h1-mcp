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
    base_url: String,
    tool_router: ToolRouter<HackerOneMcp>,
}

// Private helpers — separate impl block so the #[tool_router] macro only sees
// the tool methods below.
impl HackerOneMcp {
    async fn h1_get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
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
        let url = format!("{}{path}", self.base_url);
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
        let url = format!("{}{path}", self.base_url);
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
            base_url: H1_API.to_string(),
            tool_router: Self::tool_router(),
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
        let path = format!("/me/programs?page[number]={}", p.page.unwrap_or(1));
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

// ── Test helpers ──────────────────────────────────────────────────────────────

#[cfg(test)]
impl HackerOneMcp {
    fn new_with_base_url(username: String, token: String, base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("hackerone-mcp/0.1.0")
            .build()
            .expect("Failed to build reqwest client");
        Self {
            client,
            username,
            token,
            base_url,
            tool_router: Self::tool_router(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn make_server(mock: &MockServer) -> HackerOneMcp {
        HackerOneMcp::new_with_base_url(
            "testuser".to_string(),
            "testtoken".to_string(),
            mock.uri(),
        )
    }

    // ── urlencoding_simple ────────────────────────────────────────────────────

    #[test]
    fn urlencoding_alphanumeric_passthrough() {
        assert_eq!(urlencoding_simple("hello123"), "hello123");
    }

    #[test]
    fn urlencoding_unreserved_chars() {
        assert_eq!(urlencoding_simple("abc-def_ghi.jkl~"), "abc-def_ghi.jkl~");
    }

    #[test]
    fn urlencoding_empty_string() {
        assert_eq!(urlencoding_simple(""), "");
    }

    #[test]
    fn urlencoding_space() {
        assert_eq!(urlencoding_simple("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoding_ampersand_and_plus() {
        assert_eq!(urlencoding_simple("a&b+c"), "a%26b%2Bc");
    }

    #[test]
    fn urlencoding_percent_sign() {
        assert_eq!(urlencoding_simple("50%"), "50%25");
    }

    #[test]
    fn urlencoding_unicode_multibyte() {
        // "é" encodes as 0xC3 0xA9 in UTF-8
        assert_eq!(urlencoding_simple("café"), "caf%C3%A9");
    }

    #[test]
    fn urlencoding_slash_and_question() {
        assert_eq!(urlencoding_simple("a/b?c"), "a%2Fb%3Fc");
    }

    // ── pretty ────────────────────────────────────────────────────────────────

    #[test]
    fn pretty_null_value() {
        assert_eq!(HackerOneMcp::pretty(serde_json::Value::Null), "null");
    }

    #[test]
    fn pretty_object_is_indented() {
        let val = serde_json::json!({"key": "value"});
        let out = HackerOneMcp::pretty(val);
        assert!(out.contains("\"key\""));
        assert!(out.contains("\"value\""));
        assert!(out.contains('\n'), "pretty output should be multi-line");
    }

    #[test]
    fn pretty_array_wraps() {
        let val = serde_json::json!([1, 2, 3]);
        let out = HackerOneMcp::pretty(val);
        assert!(out.starts_with('['));
        assert!(out.ends_with(']'));
    }

    #[test]
    fn pretty_nested_object() {
        let val = serde_json::json!({"a": {"b": 1}});
        let out = HackerOneMcp::pretty(val);
        assert!(out.contains("\"a\""));
        assert!(out.contains("\"b\""));
    }

    // ── Input struct deserialization ──────────────────────────────────────────

    #[test]
    fn deser_get_report_input() {
        let v: GetReportInput = serde_json::from_value(serde_json::json!({"id": 42})).unwrap();
        assert_eq!(v.id, 42);
    }

    #[test]
    fn deser_list_reports_all_none() {
        let v: ListReportsInput = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(v.program.is_none());
        assert!(v.state.is_none());
        assert!(v.page.is_none());
    }

    #[test]
    fn deser_list_reports_all_set() {
        let v: ListReportsInput = serde_json::from_value(serde_json::json!({
            "program": "acme",
            "state": "triaged",
            "page": 3
        }))
        .unwrap();
        assert_eq!(v.program.as_deref(), Some("acme"));
        assert_eq!(v.state.as_deref(), Some("triaged"));
        assert_eq!(v.page, Some(3));
    }

    #[test]
    fn deser_add_comment_defaults() {
        let v: AddCommentInput = serde_json::from_value(serde_json::json!({
            "report_id": 1,
            "message": "hi"
        }))
        .unwrap();
        assert_eq!(v.report_id, 1);
        assert_eq!(v.message, "hi");
        assert!(v.internal.is_none());
    }

    #[test]
    fn deser_add_comment_internal_true() {
        let v: AddCommentInput = serde_json::from_value(serde_json::json!({
            "report_id": 1,
            "message": "secret",
            "internal": true
        }))
        .unwrap();
        assert_eq!(v.internal, Some(true));
    }

    #[test]
    fn deser_change_state_no_message() {
        let v: ChangeStateInput = serde_json::from_value(serde_json::json!({
            "report_id": 2,
            "state": "resolved"
        }))
        .unwrap();
        assert_eq!(v.report_id, 2);
        assert_eq!(v.state, "resolved");
        assert!(v.message.is_none());
    }

    #[test]
    fn deser_change_state_with_message() {
        let v: ChangeStateInput = serde_json::from_value(serde_json::json!({
            "report_id": 2,
            "state": "informative",
            "message": "see docs"
        }))
        .unwrap();
        assert_eq!(v.message.as_deref(), Some("see docs"));
    }

    #[test]
    fn deser_award_bounty_minimal() {
        let v: AwardBountyInput = serde_json::from_value(serde_json::json!({
            "report_id": 5,
            "amount": "100.00"
        }))
        .unwrap();
        assert_eq!(v.amount, "100.00");
        assert!(v.bonus_amount.is_none());
        assert!(v.message.is_none());
    }

    #[test]
    fn deser_award_bounty_full() {
        let v: AwardBountyInput = serde_json::from_value(serde_json::json!({
            "report_id": 5,
            "amount": "100.00",
            "bonus_amount": "25.00",
            "message": "nice catch"
        }))
        .unwrap();
        assert_eq!(v.bonus_amount.as_deref(), Some("25.00"));
        assert_eq!(v.message.as_deref(), Some("nice catch"));
    }

    #[test]
    fn deser_get_user_input() {
        let v: GetUserInput =
            serde_json::from_value(serde_json::json!({"username": "alice"})).unwrap();
        assert_eq!(v.username, "alice");
    }

    #[test]
    fn deser_get_program_input() {
        let v: GetProgramInput =
            serde_json::from_value(serde_json::json!({"handle": "acme"})).unwrap();
        assert_eq!(v.handle, "acme");
    }

    #[test]
    fn deser_search_reports_input() {
        let v: SearchReportsInput =
            serde_json::from_value(serde_json::json!({"keyword": "xss"})).unwrap();
        assert_eq!(v.keyword, "xss");
        assert!(v.page.is_none());
    }

    #[test]
    fn deser_get_activities_input() {
        let v: GetActivitiesInput = serde_json::from_value(serde_json::json!({
            "handle": "prog",
            "page": 2
        }))
        .unwrap();
        assert_eq!(v.handle, "prog");
        assert_eq!(v.page, Some(2));
    }

    #[test]
    fn deser_list_programs_input() {
        let v: ListProgramsInput =
            serde_json::from_value(serde_json::json!({"page": 5})).unwrap();
        assert_eq!(v.page, Some(5));
    }

    // ── HTTP integration tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn get_user_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"data": {"attributes": {"username": "alice"}}}),
            ))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_user(Parameters(GetUserInput {
                username: "alice".to_string(),
            }))
            .await;
        assert!(result.contains("alice"), "expected username in response: {result}");
    }

    #[tokio::test]
    async fn get_user_not_found_returns_error_string() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/nobody"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_user(Parameters(GetUserInput {
                username: "nobody".to_string(),
            }))
            .await;
        assert!(
            result.starts_with("Error fetching user 'nobody'"),
            "unexpected: {result}"
        );
    }

    #[tokio::test]
    async fn get_report_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/reports/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": {"id": "42"}})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_report(Parameters(GetReportInput { id: 42 }))
            .await;
        assert!(result.contains("\"id\""), "unexpected: {result}");
    }

    #[tokio::test]
    async fn get_report_error_returns_error_string() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/reports/99"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_report(Parameters(GetReportInput { id: 99 }))
            .await;
        assert!(result.contains("Error fetching report 99"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn list_reports_returns_data() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/reports"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .list_reports(Parameters(ListReportsInput {
                program: None,
                state: None,
                page: None,
            }))
            .await;
        assert!(result.contains("data"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn change_report_state_invalid_state_rejected() {
        let mock = MockServer::start().await;
        let server = make_server(&mock).await;

        let result = server
            .change_report_state(Parameters(ChangeStateInput {
                report_id: 1,
                state: "banana".to_string(),
                message: None,
            }))
            .await;
        assert!(
            result.contains("Unknown state 'banana'"),
            "unexpected: {result}"
        );
    }

    #[tokio::test]
    async fn change_report_state_valid_states_accepted() {
        for state in &[
            "resolved",
            "not-applicable",
            "informative",
            "duplicate",
            "spam",
            "needs-more-info",
            "triaged",
            "new",
        ] {
            let mock = MockServer::start().await;
            Mock::given(method("PATCH"))
                .and(path("/reports/10/state"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"data": {"attributes": {"state": state}}}),
                ))
                .mount(&mock)
                .await;

            let server = make_server(&mock).await;
            let result = server
                .change_report_state(Parameters(ChangeStateInput {
                    report_id: 10,
                    state: state.to_string(),
                    message: None,
                }))
                .await;
            assert!(
                !result.starts_with("Unknown state"),
                "state '{state}' was unexpectedly rejected: {result}"
            );
        }
    }

    #[tokio::test]
    async fn change_report_state_with_message_posts_comment() {
        let mock = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/reports/10/state"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"data": {"attributes": {"state": "resolved"}}}),
            ))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/reports/10/comments"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"data": {"type": "comment"}})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .change_report_state(Parameters(ChangeStateInput {
                report_id: 10,
                state: "resolved".to_string(),
                message: Some("Closing this out.".to_string()),
            }))
            .await;
        assert!(result.contains("resolved"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn add_comment_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/reports/5/comments"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"data": {"type": "comment"}})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .add_comment(Parameters(AddCommentInput {
                report_id: 5,
                message: "hello".to_string(),
                internal: None,
            }))
            .await;
        assert!(result.contains("comment"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn add_comment_error_returns_error_string() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/reports/5/comments"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .add_comment(Parameters(AddCommentInput {
                report_id: 5,
                message: "hi".to_string(),
                internal: None,
            }))
            .await;
        assert!(result.contains("Error adding comment"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn award_bounty_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/reports/7/bounty"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"data": {"type": "bounty"}})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .award_bounty(Parameters(AwardBountyInput {
                report_id: 7,
                amount: "500.00".to_string(),
                bonus_amount: None,
                message: None,
            }))
            .await;
        assert!(result.contains("bounty"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn award_bounty_with_bonus_and_message() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/reports/7/bounty"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"data": {"type": "bounty"}})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .award_bounty(Parameters(AwardBountyInput {
                report_id: 7,
                amount: "500.00".to_string(),
                bonus_amount: Some("100.00".to_string()),
                message: Some("Great find!".to_string()),
            }))
            .await;
        assert!(result.contains("bounty"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn list_programs_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/programs"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .list_programs(Parameters(ListProgramsInput { page: None }))
            .await;
        assert!(result.contains("data"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn get_program_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/programs/acme"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"data": {"attributes": {"handle": "acme"}}}),
            ))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_program(Parameters(GetProgramInput {
                handle: "acme".to_string(),
            }))
            .await;
        assert!(result.contains("acme"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn get_program_error_returns_error_string() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/programs/nope"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_program(Parameters(GetProgramInput {
                handle: "nope".to_string(),
            }))
            .await;
        assert!(result.contains("Error fetching program 'nope'"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn get_activities_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/incremental/activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .get_activities(Parameters(GetActivitiesInput {
                handle: "acme".to_string(),
                page: None,
            }))
            .await;
        assert!(result.contains("data"), "unexpected: {result}");
    }

    #[tokio::test]
    async fn search_reports_success() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/reports"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
            )
            .mount(&mock)
            .await;

        let server = make_server(&mock).await;
        let result = server
            .search_reports(Parameters(SearchReportsInput {
                keyword: "xss".to_string(),
                page: None,
            }))
            .await;
        assert!(result.contains("data"), "unexpected: {result}");
    }
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
