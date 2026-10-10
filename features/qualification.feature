@specified @m1_fixture_bound @local_simulation @qualification
Feature: Qualification is earned by an exact procedure under measured conditions
  Qualification establishes eligibility for policy review; it does not itself
  authorize a model-registry mutation.

  Background:
    Given a disposable model registry for environment "demo-a"
    And deterministic skill "release-model" has revision "skill-v1"
    And qualification policy "qual-policy-v1" requires 3 fresh independent shadow passes
    And the independent checker reads registry state through its own observation interface

  @BDD-001
  Scenario: Fresh independent outcomes qualify the tested revision and context
    Given 3 distinct shadow attempts for "skill-v1" in "demo-a" have independently verified PASS outcomes
    And all outcomes are inside the qualification evidence window
    When qualification is evaluated
    Then the qualification is ELIGIBLE for "skill-v1" in "demo-a"
    And it references all 3 attempt IDs and their evidence digests
    And it binds the checker revision and qualification-policy revision
    And no passport grant has been issued
    And no live registry mutation has occurred

  @BDD-002
  Scenario: The procedure's own success message is not independent evidence
    Given the procedure reports success on 3 shadow attempts
    And no independent checker outcome exists for those attempts
    When qualification is evaluated
    Then the qualification disposition is HOLD
    And the reason is INSUFFICIENT_EVIDENCE
    And no passport grant is issued

  @BDD-003
  Scenario Outline: Evidence cannot transfer outside its tested binding
    Given a fresh eligible qualification for "skill-v1" in "demo-a"
    When eligibility is requested for revision "<revision>" in context "<context>"
    Then eligibility is rejected with reason "<reason>"
    And the original qualification remains unchanged

    Examples:
      | case                | revision | context | reason                    |
      | changed-skill       | skill-v2 | demo-a  | SKILL_REVISION_MISMATCH   |
      | changed-environment | skill-v1 | demo-b  | QUALIFICATION_CONTEXT_MISMATCH |

  @BDD-004
  Scenario: Unknown outcomes do not count as success or failure
    Given 2 distinct independent PASS outcomes and 1 UNKNOWN outcome
    When qualification is evaluated
    Then the qualification disposition is HOLD
    And the reason is EVIDENCE_UNCONFIRMED
    And its counted passes equal 2
    And its counted failures equal 0
    And no passport grant is issued
    And the UNKNOWN reason remains available for review

  @BDD-005
  Scenario: Stale evidence cannot qualify a new grant
    Given 3 independent PASS outcomes outside the permitted evidence window
    When qualification is evaluated at the controlled current time
    Then the qualification disposition is HOLD
    And the reason is STALE_EVIDENCE
    And the historical outcomes remain PASS
    And no passport grant is issued

  @BDD-006
  Scenario: Duplicate deliveries cannot inflate qualification evidence
    Given 1 independently verified shadow attempt is delivered 3 times
    When qualification is evaluated
    Then exactly 1 distinct attempt is counted
    And the qualification disposition is HOLD
    And the reason is INSUFFICIENT_EVIDENCE

  @BDD-007
  Scenario: A known failure in the selected window prevents qualification
    Given 3 independent PASS outcomes and 1 independent FAIL outcome in the selected window
    When qualification is evaluated
    Then the qualification is INELIGIBLE
    And the reason is KNOWN_FAILURE
    And all 4 outcomes remain in the evidence history
