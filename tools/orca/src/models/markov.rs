use std::{slice::Iter, time::Duration};

use crate::{
    error::Error,
    model::{self, ActorModel, Transition, TransitionAction, TransitionResult},
    run::EventRecord,
    state::Person,
};
use async_trait::async_trait;
use kanidm_client::KanidmClient;
use ndarray::{arr2, Array1, Array2, ArrayView2};
use rand::{
    distributions::{self, Distribution},
    rngs::StdRng,
    Rng, SeedableRng,
};
use statrs::distribution::{Multinomial, Normal};
use strum::EnumCount;
use strum_macros::EnumCount;

// The idea is to have a multinomial distribution for each state that represents
// the probabilities of each transitions from that state.
//* Huge issues with this approach! since we take the probabilities matrix from the user there are SOOO many ways things can go wrong
//* from a syntactic standpoint we need to ensure all values fall within range (between 0 and 1 if we want the probabilities already normalized)
//* and we have the right number of them.
//* We also need to safeguard the user from accidentally creating inconsistent transitions, that is we must force some transition probabilities to always be 0,
//* i.e. the prob of an Unauthenticated user updating their display_name must be 0. All this validation should be done at the SetupWizard stage??
pub(crate) struct ActorMarkov {
    state: State,
    multinomial_dists: Vec<Multinomial>,
    delay_dis: Normal,
    rng_thread: StdRng,
}

#[derive(Copy, Clone, EnumCount)]
pub(crate) enum State {
    Unauthenticated = 0,
    Authenticated = 1,
}

pub(crate) const DISTR_MATRIX_SIZE: usize = State::COUNT * TransitionAction::COUNT;

impl ActorMarkov {
    pub fn new(
        distributions_vec: &[f64],
        rng_seed: &Option<u64>,
        delay_dist_mean_and_std_dev: &Option<(f64, f64)>,
    ) -> Result<Self, Error> {
        let rows_count = State::COUNT;
        let cols_count = TransitionAction::COUNT;
        let distributions_matrix =
            ArrayView2::from_shape((rows_count, cols_count), distributions_vec).map_err(|x| {
                Error::InvalidInput(format!("Wrong number of probabilities provided: {}", x))
            })?;

        let multinomial_distributions = (0..rows_count)
            .into_iter()
            .map(|i| Multinomial::new(distributions_matrix.row(i).as_slice().unwrap(), 1).unwrap())
            .collect();

        // TODO: think about what default values would work for the default normal distribution
        let (mean, std_dev) = delay_dist_mean_and_std_dev.unwrap_or((5., 1.));
        let delay_dis = Normal::new(mean, std_dev).map_err(|x| {
            Error::InvalidInput(format!("Invalid input for the delay distribution: {}", x))
        })?;
        Ok(ActorMarkov {
            state: State::Unauthenticated,
            multinomial_dists: multinomial_distributions,
            rng_thread: StdRng::seed_from_u64(rng_seed.unwrap_or_default()),
            delay_dis,
        })
    }

    fn next_transition(&mut self) -> Transition {
        let sample = self.multinomial_dists[self.state as usize].sample(&mut self.rng_thread);

        let state_transition_index = sample.iter().position(|&x| x == 1.0).unwrap();
        let action = TransitionAction::try_from(state_transition_index as i32).unwrap();
        let delay = Some(Duration::from_secs_f32(
            self.delay_dis.sample(&mut self.rng_thread) as f32,
        ));
        Transition { delay, action }
    }

    fn next_state(&mut self, result: TransitionResult) {
        match (&self.state, result) {
            (State::Unauthenticated, TransitionResult::Ok) => {
                self.state = State::Authenticated;
            }
            (State::Unauthenticated, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
            (State::Authenticated, TransitionResult::Ok) => {
                self.state = State::Unauthenticated;
            }
            (State::Authenticated, TransitionResult::Error) => {
                self.state = State::Unauthenticated;
            }
        }
    }
}

#[async_trait]
impl ActorModel for ActorMarkov {
    async fn transition(
        &mut self,
        client: &KanidmClient,
        person: &Person,
    ) -> Result<EventRecord, Error> {
        let transition = self.next_transition();

        if let Some(delay) = transition.delay {
            tokio::time::sleep(delay).await;
        }

        // Once we get to here, we want the transition to go ahead.
        let (result, event) = match transition.action {
            TransitionAction::Login => model::login(client, person).await,
            TransitionAction::Logout => model::logout(client, person).await,
            TransitionAction::ReadAttribute => model::person_get(client, person).await,
            TransitionAction::WriteAttribute => model::person_set(client, person).await,
            _ => Err(Error::InvalidState),
        }?;

        // Given the result, make a choice about what text.
        self.next_state(result);

        Ok(event)
    }
}

#[test]
fn test_markov() {
    // let mut frequency = vec![0, 0, 0, 0, 0, 0];
    // for _ in 0..1000000 {
    //     frequency[current_state] += 1;
    //     let sample = distributions[current_state].sample(rng_seed);
    //     current_state = sample.iter().position(|&x| x == 1.0).unwrap();
    // }
    // for i in 0..6 {
    //     println!("{} frequency: {}", i, frequency[i] as f32 / 1000000.0);
    // }
}
