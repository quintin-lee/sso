#!/bin/bash
set -e

# Cleanup any previous runs
rm -f node1.toml node2.toml node3.toml
rm -f node1.db node2.db node3.db

# Create config for Node 1
cat <<EOF > node1.toml
[server]
port = 8081
log_level = "debug"

[database]
type = "sqlite3"
url = "node1.db"

[raft]
enabled = true
node_id = 1
nodes = [
    { id = 1, url = "http://127.0.0.1:8081" },
    { id = 2, url = "http://127.0.0.1:8082" },
    { id = 3, url = "http://127.0.0.1:8083" }
]
EOF

# Create config for Node 2
cat <<EOF > node2.toml
[server]
port = 8082
log_level = "debug"

[database]
type = "sqlite3"
url = "node2.db"

[raft]
enabled = true
node_id = 2
nodes = [
    { id = 1, url = "http://127.0.0.1:8081" },
    { id = 2, url = "http://127.0.0.1:8082" },
    { id = 3, url = "http://127.0.0.1:8083" }
]
EOF

# Create config for Node 3
cat <<EOF > node3.toml
[server]
port = 8083
log_level = "debug"

[database]
type = "sqlite3"
url = "node3.db"

[raft]
enabled = true
node_id = 3
nodes = [
    { id = 1, url = "http://127.0.0.1:8081" },
    { id = 2, url = "http://127.0.0.1:8082" },
    { id = 3, url = "http://127.0.0.1:8083" }
]
EOF

echo "Starting 3 Raft Nodes..."
./sso_system -c node1.toml --server > node1.log 2>&1 &
PID1=$!
./sso_system -c node2.toml --server > node2.log 2>&1 &
PID2=$!
./sso_system -c node3.toml --server > node3.log 2>&1 &
PID3=$!

function cleanup {
    echo "Stopping nodes..."
    kill $PID1 $PID2 $PID3 2>/dev/null || true
    wait $PID1 $PID2 $PID3 2>/dev/null || true
}
trap cleanup EXIT

echo "Waiting for Leader Election (5 seconds)..."
sleep 5

echo "Creating User 'raft_test_user' on Node 1 (Leader check)..."
curl --noproxy "*" -s -X POST http://127.0.0.1:8081/api/v1/users \
    -H "Content-Type: application/json" \
    -d '{"username":"raft_test_user", "password":"password123", "email":"raft@test.com"}' | jq

echo "Creating User 'raft_test_user' on Node 2 (Leader check)..."
curl --noproxy "*" -s -X POST http://127.0.0.1:8082/api/v1/users \
    -H "Content-Type: application/json" \
    -d '{"username":"raft_test_user", "password":"password123", "email":"raft@test.com"}' | jq

echo "Creating User 'raft_test_user' on Node 3 (Leader check)..."
curl --noproxy "*" -s -X POST http://127.0.0.1:8083/api/v1/users \
    -H "Content-Type: application/json" \
    -d '{"username":"raft_test_user", "password":"password123", "email":"raft@test.com"}' | jq

echo "Waiting for replication (2 seconds)..."
sleep 2

echo "Fetching User from Node 2..."
curl --noproxy "*" -s -X GET "http://127.0.0.1:8082/api/v1/users?q=raft_test_user" | jq

echo "Fetching User from Node 3..."
curl --noproxy "*" -s -X GET "http://127.0.0.1:8083/api/v1/users?q=raft_test_user" | jq

echo "Test Finished. Checking logs for Leader Election:"
grep "Raft:" node1.log node2.log node3.log | head -n 20
