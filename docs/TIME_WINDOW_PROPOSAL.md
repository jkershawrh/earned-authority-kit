# BDD-009 time-window policy proposal — unimplemented

BDD-009 remains AMBER. The canonical policy has no policy-owned release calendar. No implementation, complete patch, source pin, or live service was changed for this proposal.

A caller-defined interval alone cannot establish that policy denies release during that interval. It can only request an additional constraint. Closing the scenario requires an operator-approved policy rule and an otherwise permitted resource, with an explicit denial reason proving that the calendar caused the denial.

The proposed contract would add an optional `requested_window` containing integer epoch-millisecond `not_before_ms` and `not_after_ms`. It represents a half-open interval: the start is included and the end is excluded. The policy engine would supply current time from its own clock. Caller-supplied clocks or calendars would not be used. A decision would bind the exact requested interval and the engine's evaluation time to the existing request and immutable policy identity.

One bounded implementation could place a recurring UTC maintenance interval directly in the pinned Rego source. The policy would reject any requested release interval overlapping it, and would also deny immediate release during that interval when the request omits a window. Tests would cover equality at both boundaries, midnight crossings, full-day requests, invalid intervals, and unchanged rules for unrelated actions. This would change promotion behavior during the selected period and make positive acceptance checks sensitive to the real clock.

The maintenance interval and its operational consequences need to be selected by the policy owner. A specific interval must not be invented merely to complete BDD-009. No scheduler, configurable calendar, compatibility guarantee, or successful live acceptance is asserted here.
