# RFC 9815 BGP-LS-SPF Support Plan

## Scope

Implement receiver-side support for AFI 16388 / SAFI 80 in GoBMP.  GoBMP is a
passive BMP collector, so RFC 9815's BGP-speaker SPF decision process and
origination requirements are out of scope.

## Approach

1. Reuse the RFC 9552 BGP-LS NLRI wire decoder because RFC 9815 Section 5.1.1
   requires the same encoding.
2. Add SAFI-80 dispatch and public MP_REACH/MP_UNREACH accessors without
   changing existing exported interface signatures.
3. Validate RFC 9815 receiver-side invariants for SAFI 80 before publishing:
   direct Protocol-ID for Node/Link NLRIs and required descriptors; mandatory
   BGP-LS Attribute sequence number and link/prefix metrics when the existing
   attribute decoder exposes them.
4. Publish valid Node, Link, and Prefix NLRIs through the existing BGP-LS
   message paths; do not add a parallel message model.
5. Add unit tests for dispatch, valid parsing/publication, and each rejection
   path; run focused tests, vet, staticcheck, coverage, and the relevant Go
   suite.

## Decisions

- Reuse existing RFC 9552 structures and producers; RFC 9815 specifies the
  same NLRI and BGP-LS Attribute encodings.
- Do not implement the RFC's SPF calculation, BGP session behavior, or NLRI
  origination because those require a routing-speaker role absent from GoBMP.
