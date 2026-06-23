import os
from pymongo import MongoClient
from dotenv import load_dotenv
import certifi

load_dotenv()

# Fetch MongoDB URI from environment variables
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    # Default fallback to local mongodb for development/testing
    mongo_uri = "mongodb://localhost:27017/secure_vault"

# Create a single global MongoDB client.
# Use certifi for TLS verification if connecting to a remote or Atlas cluster.
client_kwargs = {}
if mongo_uri.startswith("mongodb+srv") or "ssl=true" in mongo_uri.lower() or "tls=true" in mongo_uri.lower():
    client_kwargs["tlsCAFile"] = certifi.where()

# Set a 3-second connection timeout to detect unreachable Atlas clusters quickly
client_kwargs["serverSelectionTimeoutMS"] = 3000

use_mock = False
try:
    client = MongoClient(mongo_uri, **client_kwargs)
    # Ping the server to test connection viability
    client.admin.command('ping')
except Exception as conn_err:
    import sys
    print(f"WARNING: MongoDB connection failed ({conn_err}). Falling back to in-memory mongomock database.", file=sys.stderr)
    try:
        import mongomock
        client = mongomock.MongoClient()
        use_mock = True
    except ImportError:
        # If mongomock isn't installed, raise connection error
        raise conn_err

# Retrieve database. MongoDB Atlas URIs usually specify a default database in the path.
# If no default is specified, we fall back to 'secure_vault'.
try:
    db = client.get_default_database()
    if db is None:
        db = client["secure_vault"]
except Exception:
    db = client["secure_vault"]

# Collections definitions
users_col = db["users"]
notes_col = db["notes"]
files_col = db["files"]
logs_col = db["logs"]

# Ensure proper indexing for performance and constraints
# 1. Unique index on user email to prevent duplicate accounts
users_col.create_index("email", unique=True)

# 2. Index on user_id for faster note lookups
notes_col.create_index("user_id")

# 3. Index on user_id for file metadata retrieval
files_col.create_index("user_id")

# 4. Compound index on logs for user auditing and chronological log views
logs_col.create_index([("user_id", 1), ("timestamp", -1)])
