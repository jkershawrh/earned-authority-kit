@specified @m1_fixture_bound @local_simulation @lifecycle
Feature: Withdraw only affected authority and require evidence for reinstatement
  Background:
    Given agent "agent-a" has active logical grants for "release-model" and "read-health"
    And each grant binds a separate skill revision and qualification

  @BDD-023
  Scenario: An independent known failure demotes and revokes the affected skill
    Given an independent FAIL outcome is accepted for "release-model"
    And the remote ledger is unavailable while authenticated local outbox writes remain durable
    When the lifecycle policy applies the outcome
    Then "release-model" is DEMOTED
    And its grant is REVOKED
    And revocation acknowledgement does not wait for a remote ledger receipt
    And the revocation event remains durably queued with ledger delivery PENDING
    And the next release attempt is denied before registry mutation
    And the evidence identifies the failed attempt and the revocation revision

  @BDD-024
  Scenario: Selective withdrawal preserves unrelated valid permission
    Given the "release-model" grant has been revoked after a known failure
    When the agent requests "read-health" under its unaffected qualification
    Then the request remains authorized
    And the new effective passport contains the unchanged "read-health" grant
    And the previous passport revision cannot revive "release-model"

  @BDD-025
  Scenario Outline: Uncertain evidence holds authority without inventing a failure
    Given the required "release-model" evidence becomes "<state>"
    When the lifecycle policy reevaluates authority
    Then new release mutations are HELD with reason "<reason>"
    And the affected qualification disposition is HOLD
    And no new FAIL outcome is recorded
    And "read-health" remains authorized under its unaffected qualification

    Examples:
      | case           | state   | reason               |
      | missing-result | UNKNOWN | EVIDENCE_UNCONFIRMED  |
      | old-result     | STALE   | STALE_EVIDENCE        |

  @BDD-026
  Scenario: A revised skill earns fresh eligibility before reinstatement
    Given "release-model" revision "skill-v1" was demoted
    And revision "skill-v2" has 3 fresh independent shadow PASS outcomes in the required context
    When "skill-v2" passes qualification and receives separate policy approval
    Then a new grant is issued for "skill-v2" and its new qualification
    And "skill-v1" remains unauthorized
    And the reinstatement record references both the new evidence and prior withdrawal

  @BDD-027
  Scenario: A manual status flip cannot bypass qualification or policy
    Given "release-model" was demoted and has no current eligible qualification
    When a request attempts to mark its grant active without evidence and policy approval
    Then the request is DENIED
    And the revoked grant remains ineffective
