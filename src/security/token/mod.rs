//! Token lifecycle — revocation and abuse prevention.
//!
//! | Module          | Status  | Notes                                    |
//! |-----------------|---------|------------------------------------------|
//! | [`blocklist`]   | Active | JWT revocation via JTI blocklist         |
//! | [`brute_force`] | Active | Failed auth attempt tracking and lockout |

pub mod blocklist;
pub mod brute_force;
