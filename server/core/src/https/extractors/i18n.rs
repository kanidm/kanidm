use axum::extract::FromRequestParts;
use hyper::header::ACCEPT_LANGUAGE;
use unic_langid::LanguageIdentifier;

pub(crate) struct AcceptLanguage(pub Vec<LanguageIdentifier>);

impl<S> FromRequestParts<S> for AcceptLanguage
where
    S: Send + Sync,
{
    type Rejection = ();

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let mut languages: Vec<(LanguageIdentifier, f32)> = parts
            .headers
            .get(ACCEPT_LANGUAGE)
            .map(|values| values.to_str().ok())
            .flatten()
            .unwrap_or_default()
            .split(',')
            .map(|value| value.split_once(';').unwrap_or((value, "1")))
            .filter_map(|(language, quality)| language.parse().ok().zip(quality.parse().ok()))
            .collect();

        languages.sort_by(|a, b| b.1.total_cmp(&a.1));

        Ok(Self(
            languages
                .into_iter()
                .map(|(language, _)| language)
                .collect(),
        ))
    }
}
