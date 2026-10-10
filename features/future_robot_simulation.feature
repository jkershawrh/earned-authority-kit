@specified @unbound @future @simulation_only
Feature: Future robot simulation reuses qualified-context permissions
  This specification is outside the first model-registry release gate. It makes
  no assertion about physical stopping, collision avoidance, or hardware safety.

  @BDD-038
  Scenario: A changed simulated aisle invalidates permission for the next command
    Given a simulated scan procedure is qualified only for aisle configuration "aisle-a-v1"
    And an active grant permits that procedure only in "aisle-a-v1"
    When the simulator reports configuration "aisle-a-v2"
    Then the next scan command is refused under the old grant
    And eligibility for "aisle-a-v2" requires new independent simulation evidence and policy approval
    And the report is labeled SIMULATION_ONLY
    And it makes no claim that a real robot was stopped or made safe
