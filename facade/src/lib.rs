//! # wallet8 - the namespace facade
//!
//! Every wallet8 crate imports through the workspace's namespace:
//! `use wallet8::oid4vci::*`, `use wallet8::oid4vp::*`, `use
//! wallet8::holder::contracts::*`. Consumers (a vertical's own wallet
//! service, the reference wallet app's backend) depend on THIS crate
//! as the single git dependency - never a bare leaf.
//!
//! The leaf crates:
//!
//! - [`oid4vci`] - the OID4VCI wallet client (issuance).
//! - [`oid4vp`] - the OID4VP wallet client (presentation).
//! - [`holder`] - the holder-service contracts (the vault rows).

/// The OID4VCI wallet client.
pub mod oid4vci {
    pub use wallet8_oid4vci_client::*;
}

/// The OID4VP wallet client.
pub mod oid4vp {
    pub use wallet8_oid4vp_client::*;
}

/// The holder-service contracts.
pub mod holder {
    pub use wallet8_holder_contracts as contracts;
}
