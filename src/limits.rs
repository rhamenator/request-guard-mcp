use crate::error::AppError;

/// Enforce request-level limits.
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_batch_size: usize,
}

impl Limits {
    pub fn check_request_size(&self, bytes: usize) -> Result<(), AppError> {
        if bytes > self.max_request_bytes {
            Err(AppError::RequestTooLarge)
        } else {
            Ok(())
        }
    }

    pub fn check_batch_size(&self, got: usize) -> Result<(), AppError> {
        if got > self.max_batch_size {
            Err(AppError::BatchTooLarge {
                max: self.max_batch_size,
                got,
            })
        } else {
            Ok(())
        }
    }
}
