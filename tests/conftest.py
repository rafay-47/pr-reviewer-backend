"""
Pytest configuration and fixtures.
"""

import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_env_vars():
    """Mock environment variables for testing."""
    with patch.dict(os.environ, {
        "LLM_PROVIDER": "claude",
        "LLM_API_KEY": "test-api-key-not-real",
        "API_AUTH_TOKEN": "",  # Disable auth for tests
        "LOG_LEVEL": "WARNING",
    }):
        yield


@pytest.fixture
def sample_diff():
    """Sample git diff for testing."""
    return """diff --git a/src/controllers/userController.js b/src/controllers/userController.js
index 1234567..abcdefg 100644
--- a/src/controllers/userController.js
+++ b/src/controllers/userController.js
@@ -45,6 +45,12 @@ async function getUser(req, res) {
   const userId = req.params.id;
-  const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
+  const query = `SELECT * FROM users WHERE id = ${userId}`;
+  const user = await db.query(query);
   res.json(user);
 }
"""


@pytest.fixture
def safe_diff():
    """A diff that should not contain security issues."""
    return """diff --git a/README.md b/README.md
index 1234567..abcdefg 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,5 @@
 # My App
 
+This is a description of my app.
+
 Welcome to my application!
"""


@pytest.fixture
def sql_injection_diff():
    """Diff containing SQL injection vulnerability."""
    return """diff --git a/src/db/queries.js b/src/db/queries.js
index abc1234..def5678 100644
--- a/src/db/queries.js
+++ b/src/db/queries.js
@@ -10,6 +10,15 @@ const pool = require('./pool');
+async function findUserByEmail(email) {
+  const query = "SELECT * FROM users WHERE email = '" + email + "'";
+  const result = await pool.query(query);
+  return result.rows[0];
+}
+
+module.exports = { findUserByEmail };
"""


@pytest.fixture
def hardcoded_secret_diff():
    """Diff containing hardcoded secrets."""
    return """diff --git a/src/config/api.js b/src/config/api.js
index abc1234..def5678 100644
--- a/src/config/api.js
+++ b/src/config/api.js
@@ -1,5 +1,8 @@
 module.exports = {
   apiUrl: 'https://api.example.com',
+  apiKey: 'sk-1234567890abcdef1234567890abcdef',
+  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
+  databasePassword: 'super_secret_password_123',
 };
"""


@pytest.fixture
def command_injection_diff():
    """Diff containing command injection vulnerability."""
    return """diff --git a/src/utils/file-handler.js b/src/utils/file-handler.js
index abc1234..def5678 100644
--- a/src/utils/file-handler.js
+++ b/src/utils/file-handler.js
@@ -1,5 +1,12 @@
 const { exec } = require('child_process');
 
+function convertFile(filename) {
+  exec(`convert ${filename} output.pdf`, (error, stdout, stderr) => {
+    if (error) console.error(error);
+  });
+}
+
+module.exports = { convertFile };
"""


@pytest.fixture
def path_traversal_diff():
    """Diff containing path traversal vulnerability."""
    return """diff --git a/src/routes/files.js b/src/routes/files.js
index abc1234..def5678 100644
--- a/src/routes/files.js
+++ b/src/routes/files.js
@@ -5,6 +5,12 @@ const path = require('path');
 
+app.get('/download', (req, res) => {
+  const filename = req.query.file;
+  const filepath = path.join('/uploads', filename);
+  res.sendFile(filepath);
+});
"""

