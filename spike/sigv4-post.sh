#!/bin/sh
# sigv4-post.sh — hand-rolled AWS SigV4 for AWS JSON 1.1 APIs, POSIX sh + openssl only.
#
# Exists because Haiku/arm64 has no Go and no AWS CLI. This is the Stage 1 spike tool
# and the reference implementation for the C++ signer in haiku-mgmt-agent.
#
# Usage: sigv4-post.sh <service> <target-prefix> <operation> <json-body>
#   e.g. sigv4-post.sh ssm         AmazonSSM                        UpdateInstanceInformation '{...}'
#        sigv4-post.sh ec2messages EC2WindowsMessageDeliveryService GetMessages              '{...}'
#
# Credentials, in order of preference:
#   1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN from the environment
#   2. IMDSv2 instance role (169.254.169.254) — the Haiku path
# Region: AWS_REGION, else IMDSv2 placement, else us-west-2.
#
# Env knobs:
#   OPENSSL     path to openssl        (default: openssl)
#   CURL_CA     value for curl --cacert (open question #3; unset = use system store)
#   SIGV4_DEBUG 1 = dump canonical request + string-to-sign to stderr

set -e

SERVICE="$1"
TARGET_PREFIX="$2"
OPERATION="$3"
BODY="$4"

[ -n "$SERVICE" ] && [ -n "$TARGET_PREFIX" ] && [ -n "$OPERATION" ] && [ -n "$BODY" ] || {
    echo "usage: $0 <service> <target-prefix> <operation> <json-body>" >&2
    exit 2
}

OPENSSL="${OPENSSL:-openssl}"
IMDS="169.254.169.254"
CURL_EXTRA=""
[ -n "$CURL_CA" ] && CURL_EXTRA="--cacert $CURL_CA"

# ---------- primitives ----------

sha256_hex() { printf '%s' "$1" | "$OPENSSL" dgst -sha256 | sed 's/^.*= *//'; }
hmac_hex()   { printf '%s' "$2" | "$OPENSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$1" | sed 's/^.*= *//'; }
to_hex()     { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# ---------- credentials ----------

imds_token() {
    curl -s -m 5 -X PUT "http://$IMDS/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null
}

# JSON scalar extraction without jq (Haiku base install has no jq).
json_str() { printf '%s' "$2" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    AK="$AWS_ACCESS_KEY_ID"; SK="$AWS_SECRET_ACCESS_KEY"; ST="$AWS_SESSION_TOKEN"
    CRED_SOURCE="env"
else
    TOKEN=$(imds_token)
    [ -n "$TOKEN" ] || { echo "FATAL: no env creds and IMDSv2 token request failed" >&2; exit 1; }
    ROLE=$(curl -s -m 5 -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://$IMDS/latest/meta-data/iam/security-credentials/" | head -1)
    [ -n "$ROLE" ] || { echo "FATAL: no IAM role in instance metadata" >&2; exit 1; }
    CREDS=$(curl -s -m 5 -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://$IMDS/latest/meta-data/iam/security-credentials/$ROLE")
    AK=$(json_str AccessKeyId "$CREDS")
    SK=$(json_str SecretAccessKey "$CREDS")
    ST=$(json_str Token "$CREDS")
    [ -n "$AK" ] && [ -n "$SK" ] || { echo "FATAL: could not parse role creds for $ROLE" >&2; exit 1; }
    CRED_SOURCE="imds:$ROLE"
fi

if [ -z "$AWS_REGION" ]; then
    [ -n "$TOKEN" ] || TOKEN=$(imds_token)
    AWS_REGION=$(curl -s -m 5 -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://$IMDS/latest/meta-data/placement/region" 2>/dev/null)
fi
REGION="${AWS_REGION:-us-west-2}"

# ---------- canonical request ----------

HOST="$SERVICE.$REGION.amazonaws.com"
AMZDATE=$(date -u +%Y%m%dT%H%M%SZ)
DATESTAMP=$(printf '%s' "$AMZDATE" | cut -c1-8)
CONTENT_TYPE="application/x-amz-json-1.1"
AMZ_TARGET="$TARGET_PREFIX.$OPERATION"
PAYLOAD_HASH=$(sha256_hex "$BODY")

if [ -n "$ST" ]; then
    CANONICAL_HEADERS="content-type:$CONTENT_TYPE
host:$HOST
x-amz-date:$AMZDATE
x-amz-security-token:$ST
x-amz-target:$AMZ_TARGET
"
    SIGNED_HEADERS="content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
else
    CANONICAL_HEADERS="content-type:$CONTENT_TYPE
host:$HOST
x-amz-date:$AMZDATE
x-amz-target:$AMZ_TARGET
"
    SIGNED_HEADERS="content-type;host;x-amz-date;x-amz-target"
fi

CANONICAL_REQUEST="POST
/

$CANONICAL_HEADERS
$SIGNED_HEADERS
$PAYLOAD_HASH"

SCOPE="$DATESTAMP/$REGION/$SERVICE/aws4_request"
STRING_TO_SIGN="AWS4-HMAC-SHA256
$AMZDATE
$SCOPE
$(sha256_hex "$CANONICAL_REQUEST")"

if [ "$SIGV4_DEBUG" = "1" ]; then
    echo "--- creds: $CRED_SOURCE / region: $REGION ---" >&2
    echo "--- canonical request ---" >&2; printf '%s\n' "$CANONICAL_REQUEST" >&2
    echo "--- string to sign ---" >&2;   printf '%s\n' "$STRING_TO_SIGN" >&2
fi

# ---------- signing key ----------

K_DATE=$(hmac_hex "$(to_hex "AWS4$SK")" "$DATESTAMP")
K_REGION=$(hmac_hex "$K_DATE" "$REGION")
K_SERVICE=$(hmac_hex "$K_REGION" "$SERVICE")
K_SIGNING=$(hmac_hex "$K_SERVICE" "aws4_request")
SIGNATURE=$(hmac_hex "$K_SIGNING" "$STRING_TO_SIGN")

AUTH="AWS4-HMAC-SHA256 Credential=$AK/$SCOPE, SignedHeaders=$SIGNED_HEADERS, Signature=$SIGNATURE"

# ---------- send ----------

set -- -s -S -w '\n%{http_code}' \
    -X POST "https://$HOST/" \
    -H "Content-Type: $CONTENT_TYPE" \
    -H "X-Amz-Date: $AMZDATE" \
    -H "X-Amz-Target: $AMZ_TARGET" \
    -H "Authorization: $AUTH" \
    --data-binary "$BODY"
[ -n "$ST" ] && set -- "$@" -H "X-Amz-Security-Token: $ST"
# shellcheck disable=SC2086
exec curl $CURL_EXTRA "$@"
