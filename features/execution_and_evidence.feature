@specified @m1_fixture_bound @local_simulation @execution
Feature: Every attempted mutation has independently checked and correlated evidence
  Background:
    Given an active narrow grant for "skill-v1" to release "registry-a/model-a" in "demo-a"
    And the independent checker has read access to the disposable registry
    And each logical mutation uses a unique attempt ID

  @BDD-016
  Scenario: Successful execution is proved by the observed postcondition
    Given attempt "attempt-1" requests model version "model-v2"
    And its authenticated intent has been durably stored in the local outbox
    When the authorized deterministic procedure completes
    And the independent checker observes version "model-v2" with the required health state
    Then the outcome is PASS
    And qualification, authorization, execution, observation, and ledger records share "attempt-1"
    And the execution record includes the exact skill and grant revisions
    And the command binds the exact skill, context, qualification, and policy digests
    And the mutation count is 1

  @BDD-017
  Scenario: A reported success with a wrong postcondition is a known failure
    Given the procedure reports a successful release of "model-v2"
    But the independent checker observes the registry still serving "model-v1"
    When the required observation window completes
    Then the outcome is FAIL with reason POSTCONDITION_NOT_MET
    And the procedure's reported success does not override the observation

  @BDD-018
  Scenario: An unavailable observer produces an unknown result
    Given an authorized registry mutation has completed
    And the independent checker cannot read its postcondition within the required window
    When the outcome is finalized for that window
    Then the outcome is UNKNOWN with reason OBSERVATION_UNAVAILABLE
    And the mutation is recorded as completed
    And the attempt adds neither a qualification pass nor a qualification failure
    And new mutations under the affected grant are HELD pending evidence or review

  @BDD-019
  Scenario: Retrying a completed attempt returns its result without another mutation
    Given attempt "attempt-1" completed with payload digest "payload-a"
    When the same logical attempt is retried with digest "payload-a"
    Then the original result and attempt ID are returned
    And the mutation count remains 1
    And the transport retry is linked to the original attempt

  @BDD-020
  Scenario: Reusing an attempt ID with different intent is rejected
    Given attempt "attempt-1" was accepted with payload digest "payload-a"
    When a retry supplies "attempt-1" with payload digest "payload-b"
    Then the retry is DENIED with reason IDEMPOTENCY_CONFLICT
    And no additional mutation occurs

  @BDD-021
  Scenario: Timeout after a possible commit is reconciled before retry
    Given the execution response was lost after the registry may have committed "attempt-1"
    When the caller retries "attempt-1"
    Then the adapter first reconciles the registry's durable attempt record
    And if committed it returns that commit without a second mutation
    And if commitment cannot be established it reports UNKNOWN
    And it does not blindly repeat the mutation

  @BDD-022
  Scenario: A check-only Foundation response is not execution proof
    Given Foundation reports ALLOW with "executed=false" and "receipt_created=false"
    When the kit constructs its attempt evidence
    Then it records authorization checked
    And it does not record execution completed
    And it does not record a ledger receipt as created
    And it tracks executor state, independent outcome, and ledger delivery as separate states
