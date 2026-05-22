# Architecture Decision Records

Short records of the load-bearing architectural choices in Sentinel.
Format follows [Michael Nygard's ADR template][1]: Context, Decision,
Consequences. One file per decision.

| #    | Title                                                                                       | Status   |
| ---- | ------------------------------------------------------------------------------------------- | -------- |
| 0001 | [Single CRD governs the whole lifecycle](0001-single-crd.md)                                | Accepted |
| 0002 | [One phase transition per Reconcile call](0002-one-transition-per-reconcile.md)             | Accepted |
| 0003 | [Concrete before abstract: no Detector interface in M0](0003-concrete-before-abstract.md)   | Accepted |

New ADRs go in next-numbered files; superseded ADRs are not deleted,
they get a "Status: Superseded by ADR-NNN" line at the top.

[1]: https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
