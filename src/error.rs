use thiserror::Error;

/// Application-level errors.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthenticated,

    #[error("forbidden")]
    Forbidden,

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("request too large")]
    RequestTooLarge,

    #[error("batch too large: max {max}, got {got}")]
    BatchTooLarge { max: usize, got: usize },

    #[error("tool timeout")]
    Timeout,

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("integration unavailable: {0}")]
    IntegrationUnavailable(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error")]
    Internal,
}

impl AppError {
    /// Return an HTTP-style status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            AppError::Unauthenticated => 401,
            AppError::Forbidden => 403,
            AppError::ToolNotFound(_) => 404,
            AppError::InvalidRequest(_) | AppError::Validation(_) => 400,
            AppError::RateLimitExceeded => 429,
            AppError::RequestTooLarge | AppError::BatchTooLarge { .. } => 413,
            AppError::Timeout => 504,
            AppError::Upstream(_) | AppError::IntegrationUnavailable(_) => 502,
            AppError::Serialization(_) => 422,
            AppError::Internal => 500,
        }
    }

    /// Return a machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Unauthenticated => "UNAUTHENTICATED",
            AppError::Forbidden => "FORBIDDEN",
            AppError::ToolNotFound(_) => "TOOL_NOT_FOUND",
            AppError::InvalidRequest(_) => "INVALID_REQUEST",
            AppError::Validation(_) => "VALIDATION_FAILED",
            AppError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            AppError::RequestTooLarge => "REQUEST_TOO_LARGE",
            AppError::BatchTooLarge { .. } => "BATCH_TOO_LARGE",
            AppError::Timeout => "TIMEOUT",
            AppError::Upstream(_) => "UPSTREAM_ERROR",
            AppError::IntegrationUnavailable(_) => "INTEGRATION_UNAVAILABLE",
            AppError::Serialization(_) => "SERIALIZATION_ERROR",
            AppError::Internal => "INTERNAL_ERROR",
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Serialization(e.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(_: anyhow::Error) -> Self {
        AppError::Internal
    }
}
