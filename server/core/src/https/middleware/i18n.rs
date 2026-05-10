use axum::extract::{Query, Request};
use serde::Deserialize;
use unic_langid::LanguageIdentifier;

use crate::https::{
    extractors::AcceptLanguage,
    i18n::{DEFAULT_LANGUAGE, I18N_BUNDLES},
};

#[derive(Debug, Deserialize)]
pub(crate) struct QueryParams {
    lang: Option<LanguageIdentifier>,
}

#[derive(Clone)]
pub(crate) struct I18nCtx {
    pub lang: LanguageIdentifier,
}

pub async fn i18n_layer<B>(
    Query(query): Query<QueryParams>,
    AcceptLanguage(languages): AcceptLanguage,
    mut request: Request<B>,
) -> Request<B> {
    let lang = query
        .lang
        .filter(|language| I18N_BUNDLES.contains_key(language))
        .or(languages
            .iter()
            .filter(|language| I18N_BUNDLES.contains_key(language))
            .next()
            .cloned())
        .unwrap_or(DEFAULT_LANGUAGE);

    request.extensions_mut().insert(I18nCtx { lang });

    request
}
