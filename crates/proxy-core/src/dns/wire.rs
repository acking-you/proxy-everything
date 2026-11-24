//! DNS messages for endpoint lookups.
//!
//! Queries are written by hand so their layout is exact, including the
//! experimental shape no encoder emits. Responses are decoded by
//! `hickory-proto`, which follows only backward compression pointers and so
//! terminates on pointer loops, and are then checked against the query.

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::policy::QueryShape;

/// Advertised EDNS(0) payload size: the DNS Flag Day 2020 value, which keeps
/// responses below common path MTUs.
const EDNS_UDP_PAYLOAD: u16 = 1232;
/// RFC 8467 block size for padded queries.
const PADDING_BLOCK: usize = 128;
const MAX_CNAME_HOPS: usize = 8;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
/// The offset of the first question name: a pointer to it is `0xC00C`.
const FIRST_QUESTION: [u8; 2] = [0xC0, 0x0C];
const TYPE_OPT: u16 = 41;
const OPTION_PADDING: u16 = 12;
const CLASS_IN: u16 = 1;
/// Fixed part of an OPT record: root owner, type, class, TTL and RDLENGTH.
const OPT_FIXED_LEN: usize = 11;

/// The address family a query asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    fn record_type(self) -> RecordType {
        match self {
            Self::V4 => RecordType::A,
            Self::V6 => RecordType::AAAA,
        }
    }
}

/// How a query is laid out on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    /// Plaintext transports: one question, or two with the experimental shape.
    Plain(QueryShape),
    /// DNS-over-HTTPS: one question, padded so its length hides the name.
    Padded,
}

/// A hostname in the form a query carries: lowercase ASCII labels, already
/// IDNA-encoded, without the root label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryName {
    text: String,
    name: Name,
}

impl QueryName {
    /// Accepts DNS names only; IP literals never reach a resolver.
    pub(crate) fn parse(host: &str) -> Option<Self> {
        let text = match url::Host::parse(host).ok()? {
            url::Host::Domain(domain) => domain,
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
        };
        let text = text.strip_suffix('.').unwrap_or(&text).to_owned();
        if text.is_empty()
            || text.len() > MAX_NAME_LEN
            || !text.is_ascii()
            || text
                .split('.')
                .any(|label| label.is_empty() || label.len() > MAX_LABEL_LEN)
        {
            return None;
        }
        let name = Name::from_ascii(format!("{text}.")).ok()?;
        Some(Self { text, name })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
}

/// An encoded query and what its response must echo.
#[derive(Debug)]
pub(crate) struct Query {
    id: u16,
    name: Name,
    family: Family,
    questions: usize,
    bytes: Vec<u8>,
}

impl Query {
    /// Builds a recursive query. DoH passes ID 0 so HTTP caches can share
    /// responses (RFC 8484 §4.1); datagram transports pass a random ID.
    pub(crate) fn new(name: &QueryName, family: Family, id: u16, layout: Layout) -> Self {
        let record_type = u16::from(family.record_type());
        let (questions, edns) = match layout {
            Layout::Plain(QueryShape::Standard) | Layout::Padded => (1, true),
            Layout::Plain(QueryShape::DualQuestion) => (2, false),
        };
        let mut bytes = Vec::with_capacity(PADDING_BLOCK * 2);
        bytes.extend_from_slice(&id.to_be_bytes());
        // QR=0, OPCODE=QUERY, RD=1.
        bytes.extend_from_slice(&0x0100_u16.to_be_bytes());
        bytes.extend_from_slice(&(questions as u16).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&u16::from(edns).to_be_bytes());
        for label in name.text.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&record_type.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        if questions == 2 {
            bytes.extend_from_slice(&FIRST_QUESTION);
            bytes.extend_from_slice(&record_type.to_be_bytes());
            bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        }
        if edns {
            let options = if layout == Layout::Padded {
                let unpadded = bytes.len() + OPT_FIXED_LEN + 4;
                let padding = (PADDING_BLOCK - unpadded % PADDING_BLOCK) % PADDING_BLOCK;
                let mut option = Vec::with_capacity(4 + padding);
                option.extend_from_slice(&OPTION_PADDING.to_be_bytes());
                option.extend_from_slice(&(padding as u16).to_be_bytes());
                option.resize(4 + padding, 0);
                option
            } else {
                Vec::new()
            };
            bytes.push(0);
            bytes.extend_from_slice(&TYPE_OPT.to_be_bytes());
            bytes.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&(options.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&options);
        }
        Self {
            id,
            name: name.name.clone(),
            family,
            questions,
            bytes,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The data a response carries for the queried name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Addresses of the queried family, possibly reached through CNAMEs.
    Addresses { addresses: Vec<IpAddr>, ttl: u32 },
    /// NXDOMAIN, or NODATA when `nxdomain` is false. `ttl` is the RFC 2308
    /// negative TTL when the response carries an SOA record.
    Missing { nxdomain: bool, ttl: Option<u32> },
}

impl Answer {
    /// Whether two answers assert the same data, ignoring TTLs and order.
    pub(crate) fn same_data(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Addresses {
                    addresses: left, ..
                },
                Self::Addresses {
                    addresses: right, ..
                },
            ) => left.len() == right.len() && left.iter().all(|address| right.contains(address)),
            (
                Self::Missing { nxdomain: left, .. },
                Self::Missing {
                    nxdomain: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }
}

/// A response that answers the query it was matched against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) answer: Answer,
    pub(crate) truncated: bool,
}

/// Why a message is not a usable answer to a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// Not a DNS message, or one that ends inside a record.
    Undecodable,
    /// A well-formed message for some other transaction.
    Unrelated,
    /// The matching response reports an error.
    Failed(ResponseCode),
    /// The matching response has a CNAME loop or an overlong CNAME chain.
    BrokenAliases,
}

/// Matches `bytes` to `query` and extracts the answer for the queried name.
///
/// A two-question query may be answered with only its first question echoed:
/// resolvers that accept the shape need not repeat the redundant second one.
pub(crate) fn parse(query: &Query, bytes: &[u8]) -> Result<Response, Rejection> {
    let message = Message::from_vec(bytes).map_err(|_| Rejection::Undecodable)?;
    let header = &message.metadata;
    if header.message_type != MessageType::Response
        || header.op_code != OpCode::Query
        || header.id != query.id
        || !(1..=query.questions).contains(&message.queries.len())
        || !message.queries.iter().all(|question| {
            question.name.eq_ignore_root(&query.name)
                && question.query_type == query.family.record_type()
                && question.query_class == DNSClass::IN
        })
    {
        return Err(Rejection::Unrelated);
    }
    let truncated = header.truncation;
    let answer = match header.response_code {
        ResponseCode::NoError => {
            follow_aliases(query, &message.answers).map(|answer| match answer {
                Some(answer) => answer,
                None => Answer::Missing {
                    nxdomain: false,
                    ttl: negative_ttl(&message.authorities),
                },
            })?
        }
        ResponseCode::NXDomain => Answer::Missing {
            nxdomain: true,
            ttl: negative_ttl(&message.authorities),
        },
        code => return Err(Rejection::Failed(code)),
    };
    Ok(Response { answer, truncated })
}

/// Follows the CNAME chain from the query name and collects addresses of the
/// queried family. Records for unrelated owners, such as additional data an
/// injector adds, are ignored.
fn follow_aliases(query: &Query, records: &[Record]) -> Result<Option<Answer>, Rejection> {
    let mut owner = query.name.clone();
    let mut visited = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..=MAX_CNAME_HOPS {
        let mut addresses = Vec::new();
        let mut alias = None;
        for record in records
            .iter()
            .filter(|record| record.dns_class == DNSClass::IN && record.name.eq_ignore_root(&owner))
        {
            let address = match (&record.data, query.family) {
                (RData::A(address), Family::V4) => IpAddr::V4(address.0),
                (RData::AAAA(address), Family::V6) => IpAddr::V6(address.0),
                (RData::CNAME(target), _) => {
                    alias.get_or_insert((target.0.clone(), record.ttl));
                    continue;
                }
                _ => continue,
            };
            if !addresses.contains(&address) {
                addresses.push(address);
            }
            ttl = ttl.min(record.ttl);
        }
        if !addresses.is_empty() {
            return Ok(Some(Answer::Addresses { addresses, ttl }));
        }
        let Some((target, alias_ttl)) = alias else {
            return Ok(None);
        };
        if visited
            .iter()
            .any(|name: &Name| name.eq_ignore_root(&target))
            || target.eq_ignore_root(&owner)
        {
            return Err(Rejection::BrokenAliases);
        }
        ttl = ttl.min(alias_ttl);
        visited.push(std::mem::replace(&mut owner, target));
    }
    Err(Rejection::BrokenAliases)
}

fn negative_ttl(authorities: &[Record]) -> Option<u32> {
    authorities.iter().find_map(|record| match &record.data {
        RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
        _ => None,
    })
}

/// Whether `address` can be a remote proxy endpoint. Resolvers that sinkhole
/// a name, and some injectors, answer with addresses no remote host can
/// have; 0.0.0.0 in particular connects to the local host.
///
/// Teredo addresses (RFC 4380) are among them. One encodes a client behind a
/// NAT and the relay it reaches, so no node is published under one, while
/// every forged AAAA record of the mainland's border filter that Hoang et
/// al. (USENIX Security 2021, §5.1) collected lies in that prefix.
pub(crate) fn is_routable_endpoint(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(address) => {
            let first = address.octets()[0];
            first != 0 && first < 224
        }
        IpAddr::V6(address) => {
            let teredo = address.segments()[..2] == [0x2001, 0];
            !(address.is_unspecified() || address.is_multicast() || teredo)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{Message, Query as Question};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};

    use super::*;

    pub(crate) fn name(host: &str) -> QueryName {
        QueryName::parse(host).unwrap()
    }

    /// A response echoing the ID and questions of the encoded `request`.
    pub(crate) fn response_to_request(
        request: &[u8],
        code: ResponseCode,
        answers: Vec<Record>,
    ) -> Message {
        let request = Message::from_vec(request).unwrap();
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.response_code = code;
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.queries = request.queries;
        response.answers = answers;
        response
    }

    pub(crate) fn response_to(query: &Query, code: ResponseCode, answers: Vec<Record>) -> Message {
        response_to_request(query.bytes(), code, answers)
    }

    /// A NOERROR response to the encoded `request` with `addresses` for its
    /// first question.
    pub(crate) fn addresses_reply_to(request: &[u8], addresses: &[IpAddr]) -> Vec<u8> {
        let owner = Message::from_vec(request).unwrap().queries[0].name.clone();
        let records = addresses
            .iter()
            .map(|address| match address {
                IpAddr::V4(v4) => Record::from_rdata(owner.clone(), 300, RData::A(A(*v4))),
                IpAddr::V6(v6) => Record::from_rdata(owner.clone(), 300, RData::AAAA(AAAA(*v6))),
            })
            .collect();
        response_to_request(request, ResponseCode::NoError, records)
            .to_vec()
            .unwrap()
    }

    pub(crate) fn addresses_reply(query: &Query, addresses: &[IpAddr]) -> Vec<u8> {
        addresses_reply_to(query.bytes(), addresses)
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn standard(host: &str, family: Family) -> Query {
        Query::new(
            &name(host),
            family,
            0x1234,
            Layout::Plain(QueryShape::Standard),
        )
    }

    #[test]
    fn query_names_are_normalized_and_validated() {
        assert_eq!(name("Node.Example.COM.").as_str(), "node.example.com");
        assert_eq!(name("bücher.example").as_str(), "xn--bcher-kva.example");
        for invalid in ["", ".", "a..b", "1.2.3.4", "[::1]", "127.1", "bad host"] {
            assert!(QueryName::parse(invalid).is_none(), "{invalid}");
        }
        assert!(QueryName::parse(&format!("{}.example", "a".repeat(64))).is_none());
        let long = vec!["a".repeat(63); 4].join(".");
        assert!(QueryName::parse(&long).is_none());
        assert!(QueryName::parse(&long[..253]).is_some());
    }

    #[test]
    fn standard_query_has_one_question_and_edns() {
        let query = standard("node.example", Family::V4);
        let bytes = query.bytes();
        assert_eq!(
            &bytes[..12],
            [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]
        );
        let decoded = Message::from_vec(bytes).unwrap();
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].query_type, RecordType::A);
        let edns = decoded.edns.expect("OPT record");
        assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD);
    }

    #[test]
    fn padded_query_fills_whole_blocks() {
        for host in ["a.example", "node.example.com", &"x".repeat(60)] {
            let query = Query::new(&name(host), Family::V6, 0, Layout::Padded);
            assert_eq!(query.bytes().len() % PADDING_BLOCK, 0, "{host}");
            let decoded = Message::from_vec(query.bytes()).unwrap();
            assert_eq!(decoded.metadata.id, 0);
            assert_eq!(decoded.queries[0].query_type, RecordType::AAAA);
        }
    }

    #[test]
    fn dual_question_query_points_back_to_the_first_name() {
        let query = Query::new(
            &name("node.example"),
            Family::V4,
            7,
            Layout::Plain(QueryShape::DualQuestion),
        );
        let bytes = query.bytes();
        // QDCOUNT=2, ARCOUNT=0, and the second QNAME is the pointer 0xC00C.
        assert_eq!(&bytes[4..6], [0, 2]);
        assert_eq!(&bytes[10..12], [0, 0]);
        let tail = &bytes[bytes.len() - 6..];
        assert_eq!(tail, [0xC0, 0x0C, 0, 1, 0, 1]);
        let decoded = Message::from_vec(bytes).unwrap();
        assert_eq!(decoded.queries.len(), 2);
        assert_eq!(decoded.queries[0], decoded.queries[1]);
        assert!(decoded.edns.is_none());
    }

    #[test]
    fn matching_response_yields_its_addresses() {
        let query = standard("node.example", Family::V4);
        let reply = addresses_reply(&query, &[v4([203, 0, 113, 7]), v4([203, 0, 113, 8])]);
        let response = parse(&query, &reply).unwrap();
        assert!(!response.truncated);
        assert_eq!(
            response.answer,
            Answer::Addresses {
                addresses: vec![v4([203, 0, 113, 7]), v4([203, 0, 113, 8])],
                ttl: 300
            }
        );
    }

    #[test]
    fn mismatched_transactions_are_unrelated() {
        let query = standard("node.example", Family::V4);
        let answer = [v4([203, 0, 113, 7])];

        let other_id = Query::new(
            &name("node.example"),
            Family::V4,
            0x4321,
            Layout::Plain(QueryShape::Standard),
        );
        assert_eq!(
            parse(&query, &addresses_reply(&other_id, &answer)),
            Err(Rejection::Unrelated)
        );

        let other_name = standard("other.example", Family::V4);
        assert_eq!(
            parse(&query, &addresses_reply(&other_name, &answer)),
            Err(Rejection::Unrelated)
        );

        let other_type = standard("node.example", Family::V6);
        assert_eq!(
            parse(&query, &addresses_reply(&other_type, &answer)),
            Err(Rejection::Unrelated)
        );

        // The query itself, reflected back, is not a response.
        assert_eq!(parse(&query, query.bytes()), Err(Rejection::Unrelated));

        // A two-question query may be answered with its first question alone,
        // but no reply may echo more questions than were asked, or none.
        let dual = Query::new(
            &name("node.example"),
            Family::V4,
            0x1234,
            Layout::Plain(QueryShape::DualQuestion),
        );
        assert!(parse(&dual, &addresses_reply(&query, &answer)).is_ok());
        assert!(parse(&dual, &addresses_reply(&dual, &answer)).is_ok());
        assert_eq!(
            parse(&query, &addresses_reply(&dual, &answer)),
            Err(Rejection::Unrelated)
        );
        let mut bare = Message::from_vec(&addresses_reply(&query, &answer)).unwrap();
        bare.queries.clear();
        assert_eq!(
            parse(&query, &bare.to_vec().unwrap()),
            Err(Rejection::Unrelated)
        );
    }

    #[test]
    fn question_names_match_case_insensitively() {
        let query = standard("node.example", Family::V4);
        let mut reply =
            Message::from_vec(&addresses_reply(&query, &[v4([203, 0, 113, 7])])).unwrap();
        reply.queries = vec![Question::query(
            Name::from_ascii("NODE.Example.").unwrap(),
            RecordType::A,
        )];
        assert!(parse(&query, &reply.to_vec().unwrap()).is_ok());
    }

    #[test]
    fn records_of_other_owners_and_families_are_ignored() {
        let query = standard("node.example", Family::V4);
        let mut reply = response_to(&query, ResponseCode::NoError, Vec::new());
        let other = Name::from_ascii("ads.example.").unwrap();
        reply.answers = vec![
            Record::from_rdata(other, 60, RData::A(A(Ipv4Addr::new(198, 51, 100, 1)))),
            Record::from_rdata(
                query.name.clone(),
                60,
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            ),
        ];
        assert_eq!(
            parse(&query, &reply.to_vec().unwrap()).unwrap().answer,
            Answer::Missing {
                nxdomain: false,
                ttl: None
            }
        );
    }

    #[test]
    fn cname_chains_are_followed_and_loops_rejected() {
        let query = standard("node.example", Family::V4);
        let alias = Name::from_ascii("edge.cdn.example.").unwrap();
        let records = vec![
            Record::from_rdata(
                alias.clone(),
                30,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
            ),
            Record::from_rdata(query.name.clone(), 120, RData::CNAME(CNAME(alias.clone()))),
        ];
        let reply = response_to(&query, ResponseCode::NoError, records)
            .to_vec()
            .unwrap();
        assert_eq!(
            parse(&query, &reply).unwrap().answer,
            Answer::Addresses {
                addresses: vec![v4([203, 0, 113, 9])],
                ttl: 30
            }
        );

        let looped = vec![
            Record::from_rdata(query.name.clone(), 60, RData::CNAME(CNAME(alias.clone()))),
            Record::from_rdata(alias, 60, RData::CNAME(CNAME(query.name.clone()))),
        ];
        let reply = response_to(&query, ResponseCode::NoError, looped)
            .to_vec()
            .unwrap();
        assert_eq!(parse(&query, &reply), Err(Rejection::BrokenAliases));

        let chain = (0..=MAX_CNAME_HOPS + 1)
            .map(|hop| {
                let owner = if hop == 0 {
                    query.name.clone()
                } else {
                    Name::from_ascii(format!("hop{hop}.example.")).unwrap()
                };
                let target = Name::from_ascii(format!("hop{}.example.", hop + 1)).unwrap();
                Record::from_rdata(owner, 60, RData::CNAME(CNAME(target)))
            })
            .collect();
        let reply = response_to(&query, ResponseCode::NoError, chain)
            .to_vec()
            .unwrap();
        assert_eq!(parse(&query, &reply), Err(Rejection::BrokenAliases));
    }

    #[test]
    fn negative_answers_carry_the_soa_ttl() {
        let query = standard("missing.example", Family::V4);
        let mut reply = response_to(&query, ResponseCode::NXDomain, Vec::new());
        let zone = Name::from_ascii("example.").unwrap();
        let soa = SOA::new(zone.clone(), zone.clone(), 1, 7200, 3600, 86400, 45);
        reply.authorities = vec![Record::from_rdata(zone, 900, RData::SOA(soa))];
        assert_eq!(
            parse(&query, &reply.to_vec().unwrap()).unwrap().answer,
            Answer::Missing {
                nxdomain: true,
                ttl: Some(45)
            }
        );
        let failed = response_to(&query, ResponseCode::ServFail, Vec::new())
            .to_vec()
            .unwrap();
        assert_eq!(
            parse(&query, &failed),
            Err(Rejection::Failed(ResponseCode::ServFail))
        );
    }

    #[test]
    fn truncation_is_reported() {
        let query = standard("node.example", Family::V4);
        let mut reply = response_to(&query, ResponseCode::NoError, Vec::new());
        reply.metadata.truncation = true;
        assert!(parse(&query, &reply.to_vec().unwrap()).unwrap().truncated);
    }

    /// Hand-built hostile messages: each must be rejected without panicking
    /// or looping, whatever its header claims.
    #[test]
    fn hostile_messages_are_rejected() {
        let query = standard("node.example", Family::V4);
        let mut header = query.bytes()[..12].to_vec();
        header[2] |= 0x80;
        let with = |body: &[u8], counts: [u8; 8]| {
            let mut message = header.clone();
            message[4..12].copy_from_slice(&counts);
            message.extend_from_slice(body);
            message
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("short header", header[..7].to_vec()),
            // A question whose name is a pointer to itself.
            (
                "self pointer",
                with(&[0xC0, 0x0C, 0, 1, 0, 1], [0, 1, 0, 0, 0, 0, 0, 0]),
            ),
            // Two pointers that point at each other.
            (
                "pointer cycle",
                with(
                    &[0xC0, 0x0E, 0xC0, 0x0C, 0, 1, 0, 1],
                    [0, 1, 0, 0, 0, 0, 0, 0],
                ),
            ),
            // A forward pointer past the end of the message.
            (
                "forward pointer",
                with(&[0xC0, 0xFF, 0, 1, 0, 1], [0, 1, 0, 0, 0, 0, 0, 0]),
            ),
            // A label running past the end of the message.
            (
                "overlong label",
                with(&[0x3F, b'a', b'b'], [0, 1, 0, 0, 0, 0, 0, 0]),
            ),
            // Counts promising records that are not there.
            (
                "missing records",
                with(&query.bytes()[12..], [0, 1, 0xFF, 0xFF, 0, 0, 0, 0]),
            ),
            // An A record whose RDLENGTH overruns the message.
            (
                "short rdata",
                with(
                    &[
                        &query.bytes()[12..query.bytes().len() - 11],
                        &[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 16, 1, 2],
                    ]
                    .concat(),
                    [0, 1, 0, 1, 0, 0, 0, 0],
                ),
            ),
        ];
        for (case, bytes) in cases {
            assert_eq!(parse(&query, &bytes), Err(Rejection::Undecodable), "{case}");
        }
    }

    #[test]
    fn unroutable_endpoint_addresses_are_recognized() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            "::ffff:0.0.0.0",
            "2001::1",
            "2001:0:53aa:64c:c7f:3b0d:3f57:fef4",
        ] {
            assert!(!is_routable_endpoint(address.parse().unwrap()), "{address}");
        }
        for address in [
            "203.0.113.7",
            "10.0.0.1",
            "127.0.0.1",
            "2001:db8::1",
            "2001:1::1",
            "2001:4860:4860::8888",
            "::1",
            "::ffff:203.0.113.7",
        ] {
            assert!(is_routable_endpoint(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn same_data_ignores_order_and_ttl() {
        let left = Answer::Addresses {
            addresses: vec![v4([1, 1, 1, 1]), v4([2, 2, 2, 2])],
            ttl: 5,
        };
        let right = Answer::Addresses {
            addresses: vec![v4([2, 2, 2, 2]), v4([1, 1, 1, 1])],
            ttl: 600,
        };
        let forged = Answer::Addresses {
            addresses: vec![v4([1, 1, 1, 1])],
            ttl: 5,
        };
        assert!(left.same_data(&right));
        assert!(!left.same_data(&forged));
        assert!(!forged.same_data(&Answer::Missing {
            nxdomain: true,
            ttl: None
        }));
        assert!(
            Answer::Missing {
                nxdomain: true,
                ttl: Some(1)
            }
            .same_data(&Answer::Missing {
                nxdomain: true,
                ttl: None
            })
        );
    }
}
