//! ForgeSworn Link Blossom lane.
//!
//! A hash-addressed blob-fetch protocol carried over a single ForgeSworn Link
//! [`Stream`](link_endpoint::Stream).  A storage node (Wildbloom, Bothy) uses it
//! to mirror and repair blobs over the native Link transport instead of iroh,
//! keeping the same identity, relay failover and direct-path upgrade the rest of
//! the Link stack already proves.
//!
//! The crate is split so the serving side never pulls in the client's dependency
//! on shelter-kit:
//!
//! * [`wire`] is the request/response codec.  Nothing here opens a socket.
//! * [`BlobSource`] and [`serve`] are the serving side.  A node wires its own
//!   store in through the trait, so this crate stays decoupled from any one
//!   store implementation.
//! * [`client`], behind the `shelter-kit` feature, is the fetcher.  It
//!   implements `shelter_kit::BlobFetcher` so a node can register it as one more
//!   transport lane behind the Blossom router's mirror policy.

pub mod server;
pub mod source;
pub mod wire;

#[cfg(feature = "shelter-kit")]
pub mod client;

pub use server::serve;
pub use source::{BlobBytes, BlobSource, MapBlobSource};
pub use wire::{Request, ResponseHeader, WireError};

#[cfg(feature = "shelter-kit")]
pub use client::{CardResolver, LinkFetcher, MapCardResolver};
