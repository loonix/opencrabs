//! Declared-wait cooldown for the fallback chain.
//!
//! A 429 that declares a wait parks the provider until `now + declared`. While
//! it is parked the chain routes around it; once the window lapses it is tried
//! again on its own. A 429 that declares no wait behaves as it always did.

use crate::brain::provider::cooldown::CooldownRegistry;
use crate::brain::provider::error::{INLINE_RETRY_CEILING, should_try_next_provider};
use crate::brain::provider::{
    FallbackProvider, LLMRequest, LLMResponse, Provider, ProviderError, ProviderStream,
};
use crate::utils::retry::RetryableError;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Mock that fails with a rate-limit message while `failing` is set, and
/// counts every call so a test can prove a parked entry was not touched.
struct CoolMock {
    name: String,
    failing: AtomicBool,
    wait_msg: String,
    calls: AtomicUsize,
}

impl CoolMock {
    fn new(name: &str, wait_msg: &str, failing: bool) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            failing: AtomicBool::new(failing),
            wait_msg: wait_msg.to_string(),
            calls: AtomicUsize::new(0),
        })
    }

    fn fail_now(&self) -> Option<ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            Some(ProviderError::RateLimitExceeded(self.wait_msg.clone()))
        } else {
            None
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Provider for CoolMock {
    async fn complete(
        &self,
        request: LLMRequest,
    ) -> crate::brain::provider::error::Result<LLMResponse> {
        if let Some(err) = self.fail_now() {
            return Err(err);
        }
        Ok(LLMResponse {
            id: format!("{}-response", self.name),
            model: request.model,
            content: vec![],
            stop_reason: None,
            usage: crate::brain::provider::TokenUsage {
                input_tokens: 0,
                output_tokens: 0,
                ..Default::default()
            },
            streaming_active_secs: None,
            tool_text_leak: false,
        })
    }

    async fn stream(
        &self,
        _request: LLMRequest,
    ) -> crate::brain::provider::error::Result<ProviderStream> {
        if let Some(err) = self.fail_now() {
            return Err(err);
        }
        Ok(Box::pin(futures::stream::empty()))
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn default_model(&self) -> &str {
        "mock-default"
    }

    fn supported_models(&self) -> Vec<String> {
        vec!["mock-default".to_string()]
    }

    fn context_window(&self, _model: &str) -> Option<u32> {
        Some(4096)
    }

    fn calculate_cost(&self, _model: &str, _input: u32, _output: u32) -> f64 {
        0.0
    }
}

fn request() -> LLMRequest {
    LLMRequest {
        model: "mock-default".into(),
        messages: vec![],
        system: None,
        system_suffix: None,
        max_tokens: None,
        temperature: None,
        tools: None,
        stream: false,
        metadata: None,
        working_directory: None,
        session_id: None,
    }
}

fn rate_limit(msg: &str) -> ProviderError {
    ProviderError::RateLimitExceeded(msg.to_string())
}

#[test]
fn declared_cooldown_is_uncapped() {
    let err = rate_limit("retry after 157000 s");
    assert_eq!(
        err.declared_cooldown(),
        Some(Duration::from_secs(157_000)),
        "the cooldown window must carry the full declared wait"
    );
    assert_eq!(
        err.retry_after(),
        Some(Duration::from_secs(30)),
        "the in-place retry hint stays clamped to 30s"
    );
}

#[test]
fn long_declared_wait_is_not_retryable_in_place() {
    let err = rate_limit("retry after 157000 s");
    assert!(
        !err.is_retryable(),
        "a long declared wait must not be retried in place"
    );
    assert!(
        should_try_next_provider(&err),
        "the chain must still walk on that error"
    );
}

#[test]
fn short_declared_wait_is_unchanged() {
    let err = rate_limit("retry after 5 s");
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
}

#[test]
fn declared_wait_at_the_ceiling_is_still_retried_in_place() {
    let at_ceiling = rate_limit(&format!("retry after {} s", INLINE_RETRY_CEILING.as_secs()));
    assert!(at_ceiling.is_retryable());
}

#[test]
fn registry_only_extends_and_forgets() {
    let reg = CooldownRegistry::default();
    let now = Instant::now();
    reg.park("p", now + Duration::from_secs(100));
    reg.park("p", now + Duration::from_secs(10));
    assert!(
        reg.is_cooling("p"),
        "a shorter later park must not shorten the window"
    );
    assert!(reg.has_record("p"));
    reg.forget("p");
    assert!(!reg.is_cooling("p"));
    assert!(!reg.has_record("p"));
}

#[test]
fn registry_window_lapses_but_record_stays_until_forgotten() {
    let reg = CooldownRegistry::default();
    reg.park("p", Instant::now() + Duration::from_millis(5));
    std::thread::sleep(Duration::from_millis(20));
    assert!(!reg.is_cooling("p"), "the window has lapsed");
    assert!(
        reg.has_record("p"),
        "a lapsed record is what lets the chain retry it"
    );
}

#[tokio::test]
async fn chain_skips_a_parked_primary_without_making_the_fallback_sticky() {
    let primary = CoolMock::new("primary", "retry after 157000 s", true);
    let backup = CoolMock::new("backup", "", false);
    let chain = FallbackProvider::new(primary.clone(), vec![backup.clone()]);

    // First call: primary declares a long wait, backup answers.
    chain.complete(request()).await.expect("backup answers");
    assert_eq!(primary.calls(), 1);
    assert_eq!(backup.calls(), 1);

    // Second call: the primary is parked, so it is not touched at all.
    chain
        .complete(request())
        .await
        .expect("backup answers again");
    assert_eq!(primary.calls(), 1, "a parked primary must not be retried");
    assert_eq!(backup.calls(), 2);
}

#[tokio::test]
async fn chain_returns_to_the_primary_when_its_window_lapses() {
    let primary = CoolMock::new("primary", "retry after 1 s", true);
    let backup = CoolMock::new("backup", "", false);
    let chain = FallbackProvider::new(primary.clone(), vec![backup.clone()]);

    chain.complete(request()).await.expect("backup answers");
    assert_eq!(chain.active_subprovider_name().as_deref(), Some("backup"));

    // Primary recovers and its one-second window lapses.
    primary.failing.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    chain.complete(request()).await.expect("primary answers");
    assert_eq!(primary.calls(), 2, "the lapsed primary is tried again");
    assert_eq!(
        chain.active_subprovider_name(),
        None,
        "the session is back on the primary"
    );
}

#[tokio::test]
async fn a_429_without_a_declared_wait_is_not_parked() {
    let primary = CoolMock::new("primary", "rate limited", true);
    let backup = CoolMock::new("backup", "", false);
    let chain = FallbackProvider::new(primary.clone(), vec![backup.clone()]);

    chain.complete(request()).await.expect("backup answers");
    chain.complete(request()).await.expect("backup answers");
    // Exactly as before this change: the first failure makes the backup
    // sticky and the primary is not walked again. No window was recorded.
    assert_eq!(primary.calls(), 1);
}
