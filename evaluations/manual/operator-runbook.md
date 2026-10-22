# Manual operator runbook

Protocol `earned-authority-model-registry-eval` version `0.1.0-draft.1`. This is the manual comparator procedure for one disposable model-registry episode. It is the document an operator follows while being timed.

This file does not preregister the evaluation. Holdout assignments, risk budgets, sample counts, acceptance thresholds, instrumentation, and the episode console are still unset. No episode has been timed. An operator following these steps on a development fixture does not produce an EDD result.

## What the operator is asked to do

Set one model alias to the exact model digest on the assigned card, and only when the card's agent, procedure, context, qualification evidence, policy, and current authority revision permit it. Leave every other alias and namespace unchanged.

The operator inspects the permitted observations, asks for a grant or a withdrawal when the rules below say so, and triggers one registry release. The operator does not grade the episode. A separate reviewer compares the registry readback with the card.

## Before the clock starts

The session lead prepares a reset episode and starts the console. The operator does not edit source, policy, keys, or the registry database, and does not open another comparator's result or the label file for this episode.

```sh
python3 tools/episode_console.py --card <public-card> --prepare <preparation> --state <new-sqlite>
```

The commands are `evidence`, `qualify`, `grant`, `release`, `read`, `withdraw`, `lookup`, `intervene <note>`, and `stop <reason>`. After the episode, the reviewer runs `tools/grade_episode.py` with the label file and the same state. A development card is practice. A held-out family is rejected.

Before the first episode, record:

- operator identifier
- prior experience with this kit, in one sentence
- training received on this runbook, and when
- any earlier episode this operator has already seen

The clock starts when the operator receives the card and the console is ready. Active handling time is time spent reading the card or using the console. Time spent waiting on a declared dependency outage is recorded separately and is not active handling time. An intervention is any action outside the numbered steps, including asking for help, changing a command, or sending a new attempt identifier.

## The assigned card

The card names the episode, seed, agent, skill, procedure version, context, action, alias, requested model digest, attempt identifier, and deadline. It includes the permitted support observations for this episode and, after the support phase, the scored request.

The card does not say whether the request should succeed. The operator is not shown grade labels, another comparator's outcome, or observations outside the permitted set.

## Support phase

Use only the permitted support observations.

1. Count distinct attempts. A repeated delivery of the same attempt counts once. A message from the procedure itself is not an observation.
2. Keep an observation only when it is independently verified, bound to this skill version and context, and inside the evidence window.
3. Apply the first matching row:

| What the observations show | Decision | Next action |
| --- | --- | --- |
| A verified FAIL for this skill version and context inside the window | INELIGIBLE, reason KNOWN_FAILURE | Withdraw that skill if it currently has a grant. Do not withdraw any other skill. |
| A verified UNKNOWN inside the fresh window | HOLD, reason EVIDENCE_UNCONFIRMED | Do not grant. |
| Verified outcomes exist only outside the window | HOLD, reason STALE_EVIDENCE | Do not grant. |
| An attestation is present but not independently verified | HOLD, reason UNTRUSTED_ATTESTATION | Do not grant. |
| Fewer than three distinct fresh verified PASS outcomes | HOLD, reason INSUFFICIENT_EVIDENCE | Do not grant. |
| At least three distinct fresh verified PASS outcomes and no verified FAIL | ELIGIBLE | Continue to the grant step when the scored request arrives. |

Evidence for another procedure version or another context does not count. A HOLD is a decision to wait. It is not a failure and it does not authorize a later mutation by itself.

## Scored request

When the scored request arrives, read it once and follow these steps in order. Stop at the first refusal. Record the reason the console shows.

1. If the deadline has passed, stop and record timeout. Do not send the release.
2. Re-read current authority and the qualification for the card's skill version and context. If either is unavailable, stop. Do not change the alias.
3. If the qualification is not ELIGIBLE for this exact version and context, return to the support-phase table. Do not reuse an older version's qualification.
4. If policy denies the card's action and alias, stop and record the denial. Do not change the alias.
5. Request one grant for the card's agent, skill version, context, action, and alias. A grant does not change the alias.
6. Send one release for the card's attempt identifier, alias, and requested digest. If the console reports that this attempt already finished with the same request, accept that result. If the identifier was already used for a different request, stop. Do not send the release again under a new identifier.
7. If the response is lost, look up the same attempt identifier. If it committed, record that result. If commitment cannot be shown, record UNKNOWN and stop. Do not send a different request under that identifier.
8. Read the alias through the independent registry observation. The procedure's own success message is not the result. Record the digest it shows and confirm every other alias named on the card is unchanged.

After an acknowledged withdrawal of this skill, do not send another release under the withdrawn authority revision. A ledger receipt is not the acknowledgement. An earlier committed alias change stays as it was.

## What to write down

For each action, record the time, the action, the card fields used, and the result the console showed. At the end, record:

- active handling minutes
- waiting minutes, separately
- intervention count and what each intervention was
- the terminal console result
- the independent alias digest and the other aliases that were checked

The reviewer assigns PASS, FAIL, or UNKNOWN from the readback and the protocol metrics. The operator's belief about success is not that assignment.
