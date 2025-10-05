//! Utilities for decoding the ledger predicate failures that are
//! serialized as tagged CBOR sums.  The goal of this module is to keep the
//! low-level CBOR handling in one place so the types defined in
//! `rust_rule_errors.rs` can be connected to a real decoder without having to
//! manually pattern-match every constructor.
//!
//! At the moment the module only lifts the CBOR message into a structured
//! `TaggedTree`.  A follow-up step (see the TODOs below) will translate that
//! tree into the strongly-typed enums that mirror the Haskell definitions.

use ciborium::{de, value::Value};
use std::{fmt, io};

/// Error returned while building a [`TaggedTree`].
#[derive(Debug)]
pub enum ParseError {
    /// The message could not be decoded from CBOR.
    Cbor(de::Error<std::io::Error>),
    /// The structure was not a tagged sum as expected.
    Malformed(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Cbor(err) => write!(f, "CBOR decoding error: {err}"),
            ParseError::Malformed(msg) => write!(f, "malformed predicate failure: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Cbor(err) => Some(err),
            ParseError::Malformed(_) => None,
        }
    }
}

impl From<de::Error<io::Error>> for ParseError {
    fn from(err: de::Error<io::Error>) -> Self {
        ParseError::Cbor(err)
    }
}

/// Minimal CBOR term representation that keeps ordering information for arrays
/// and key/value pairs for maps.  The intention is to resolve the term into the
/// helper structs defined in `rust_rule_errors.rs` in a later pass once we wire
/// up serde-based decoding.
#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Unsigned(u64),
    Negative(i128),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Float(f64),
    Null,
    Array(Vec<Term>),
    Map(Vec<(Term, Term)>),
    Tagged(u64, Box<Term>),
}

impl Term {
    fn from_value(value: Value) -> Term {
        match value {
            Value::Integer(int) => match int {
                ciborium::value::Integer::Pos(n) => Term::Unsigned(n),
                ciborium::value::Integer::Neg(n) => Term::Negative(n),
            },
            Value::Bytes(bytes) => Term::Bytes(bytes),
            Value::Text(text) => Term::Text(text),
            Value::Bool(b) => Term::Bool(b),
            Value::Null => Term::Null,
            Value::Float(f) => Term::Float(f),
            Value::Array(items) => {
                Term::Array(items.into_iter().map(Term::from_value).collect())
            }
            Value::Map(entries) => Term::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (Term::from_value(k), Term::from_value(v)))
                    .collect(),
            ),
            Value::Tag(tag, boxed) => {
                Term::Tagged(tag, Box::new(Term::from_value(*boxed)))
            }
            Value::Simple(simple) => Term::Unsigned(simple.into()),
        }
    }

    fn as_unsigned(&self) -> Option<u64> {
        match self {
            Term::Unsigned(value) => Some(*value),
            _ => None,
        }
    }
}

/// Representation of a CBOR-encoded sum value.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedSum {
    pub tag: u64,
    pub fields: Vec<Term>,
}

impl TaggedSum {
    fn from_term(term: Term) -> Option<TaggedSum> {
        match term {
            Term::Array(mut elements) if !elements.is_empty() => {
                let tag_term = elements.remove(0);
                let tag = tag_term.as_unsigned()?;
                Some(TaggedSum {
                    tag,
                    fields: elements,
                })
            }
            Term::Tagged(tag, boxed) => {
                if let Term::Array(mut elements) = *boxed {
                    Some(TaggedSum {
                        tag,
                        fields: elements,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Tree structure that mirrors the nesting of predicate failures.  Each node
/// is either a tagged sum (which corresponds to one constructor of a predicate
/// failure) or a leaf containing an arbitrary CBOR term.
#[derive(Debug, Clone, PartialEq)]
pub enum TaggedTree {
    Sum(TaggedSum, Vec<TaggedTree>),
    Leaf(Term),
}

impl TaggedTree {
    fn from_term(term: Term) -> TaggedTree {
        if let Some(sum) = TaggedSum::from_term(term.clone()) {
            let children = sum
                .fields
                .iter()
                .cloned()
                .map(TaggedTree::from_term)
                .collect();
            TaggedTree::Sum(sum, children)
        } else {
            TaggedTree::Leaf(term)
        }
    }
}

/// Decode a CBOR message and build a [`TaggedTree`] describing its structure.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the input cannot be interpreted as a
/// tagged sum and [`ParseError::Cbor`] if the raw bytes are not valid CBOR.
pub fn decode_predicate_failure<R: io::Read>(reader: R) -> Result<TaggedTree, ParseError> {
    let value: Value = de::from_reader(reader)?;
    let root = Term::from_value(value);
    if TaggedSum::from_term(root.clone()).is_none() {
        return Err(ParseError::Malformed("expected a tagged sum"));
    }
    Ok(TaggedTree::from_term(root))
}

/// Convenience helper for decoding from an in-memory slice.
pub fn decode_predicate_failure_bytes(bytes: &[u8]) -> Result<TaggedTree, ParseError> {
    decode_predicate_failure(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::ser::into_writer;

    #[test]
    fn round_trip_simple_sum() {
        let mut buffer = Vec::new();
        // Encode a dummy predicate failure represented as [5, [1], "payload"].
        let message = Value::Array(vec![
            Value::Integer(ciborium::value::Integer::Pos(5)),
            Value::Array(vec![Value::Integer(ciborium::value::Integer::Pos(1))]),
            Value::Text("payload".into()),
        ]);
        into_writer(&message, &mut buffer).expect("encode test value");

        let tree = decode_predicate_failure_bytes(&buffer).expect("parse tree");
        match tree {
            TaggedTree::Sum(sum, children) => {
                assert_eq!(sum.tag, 5);
                assert_eq!(children.len(), 2);
            }
            TaggedTree::Leaf(_) => panic!("expected a sum"),
        }
    }
}

// TODO: Implement translation from `TaggedTree` into the typed enums in
// `rust_rule_errors.rs` once the serde-based decoders are derived for the helper
// structures.  The intent is to walk the tree, look up the constructor metadata,
// and feed each node into `ciborium::de::from_reader` to produce the concrete
// Rust representation.
