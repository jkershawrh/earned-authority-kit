package system.authz

# Local reference service: immutable loaded policy, no network administration.
# Host/container administrators remain trusted; this is not a sandbox against them.
default allow = false

allow {
    input.method == "GET"
    input.path == ["health"]
}

allow {
    input.method == "GET"
    input.path == ["v1", "policies"]
}

allow {
    input.method == "POST"
    input.path == ["v1", "data", "are", "evaluatepolicy", "decision"]
}
