//  Copyright (c) 2026 Kaphera Limited
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Kaphera Limited - initial API and implementation
//

use async_trait::async_trait;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerationError, TransitKeyRef, TransitKeyResolver};

/// Resolves a fixed, configured transit key for every participant context.
///
/// jwtlet signs all issued tokens with a single service-wide Vault transit key
/// (`vault.key_name`), so the resolved key does not depend on the participant
/// context. The `kid` is left unset so the generator derives it from the Vault
/// key metadata (`{key_name}-{current_version}`).
pub(crate) struct StaticTransitKeyResolver {
    key_name: String,
}

impl StaticTransitKeyResolver {
    pub(crate) fn new(key_name: impl Into<String>) -> Self {
        Self {
            key_name: key_name.into(),
        }
    }
}

#[async_trait]
impl TransitKeyResolver for StaticTransitKeyResolver {
    async fn resolve(&self, _participant_context: &ParticipantContext) -> Result<TransitKeyRef, JwtGenerationError> {
        Ok(TransitKeyRef {
            key_name: self.key_name.clone(),
            kid: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn context(id: &str) -> ParticipantContext {
        ParticipantContext::builder().id(id).build()
    }

    #[tokio::test]
    async fn resolve_returns_configured_key_name_for_any_context() {
        let resolver = StaticTransitKeyResolver::new("jwtlet-signing");
        for pc in [context("jwtlet"), context("some-participant")] {
            let key = resolver.resolve(&pc).await.unwrap();
            assert_eq!(key.key_name, "jwtlet-signing");
        }
    }

    #[tokio::test]
    async fn resolve_leaves_kid_unset_for_generator_derivation() {
        let resolver = StaticTransitKeyResolver::new("jwtlet-signing");
        let key = resolver.resolve(&context("jwtlet")).await.unwrap();
        assert_eq!(key.kid, None);
    }
}
