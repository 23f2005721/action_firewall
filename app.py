from flask import Flask, request, jsonify

app = Flask(__name__)

WORKSPACE = "prod-vvbmgb"

REQUIRED_LABELS = {
    "owner": "student-cr8sq",
    "environment": "production",
    "cost_center": "cc-a0ev"
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}

ALLOWED_PROVIDER_VERSIONS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0"
}

STATEFUL_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk"
}


def reject(reason):
    return jsonify({
        "decision": "reject",
        "reason": reason
    })


@app.route("/")
def home():
    return jsonify({"status": "ok"})


@app.route("/terraform/plan", methods=["POST"])
def terraform_plan():
    data = request.get_json()

    # -------------------------------------------------
    # 1. SCHEMA VALIDATION
    # -------------------------------------------------

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return reject("INVALID_PLAN")

    expected_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource"
    }

    if set(data.keys()) != expected_top:
        return reject("INVALID_PLAN")

    if not isinstance(data["environment"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["destroyApproved"], bool):
        return reject("INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return reject("INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return reject("INVALID_PLAN")

    state = data["state"]

    if set(state.keys()) != {"backend", "locked"}:
        return reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return reject("INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return reject("INVALID_PLAN")

    resource = data["resource"]

    expected_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy"
    }

    if set(resource.keys()) != expected_resource:
        return reject("INVALID_PLAN")

    if not isinstance(resource["address"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return reject("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return reject("INVALID_PLAN")

    if (
        resource["secret"] is not None
        and not isinstance(resource["secret"], str)
    ):
        return reject("INVALID_PLAN")

    # -------------------------------------------------
    # 2. ENVIRONMENT
    # -------------------------------------------------

    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # -------------------------------------------------
    # 3. STATE SAFETY
    # -------------------------------------------------

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # -------------------------------------------------
    # 4. PROVIDER PINNING
    # -------------------------------------------------

    if data["providerVersion"] not in ALLOWED_PROVIDER_VERSIONS:
        return reject("UNPINNED_PROVIDER")

    # -------------------------------------------------
    # 5. LABELS
    # -------------------------------------------------

    labels = resource["labels"]

    for k, v in REQUIRED_LABELS.items():
        if labels.get(k) != v:
            return reject("MISSING_LABELS")

    # -------------------------------------------------
    # 6. SECRET VALIDATION
    # -------------------------------------------------

    secret = resource["secret"]

    if secret is not None:
        if len(secret.strip()) == 0:
            return reject("PLAINTEXT_SECRET")

        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

    # -------------------------------------------------
    # 7. DELETE APPROVAL
    # -------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and data["destroyApproved"] is not True
    ):
        return reject("DELETE_NOT_APPROVED")

    # -------------------------------------------------
    # 8. FORCE DESTROY
    # -------------------------------------------------

    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    return jsonify({
        "decision": "approve",
        "reason": "APPROVE"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
