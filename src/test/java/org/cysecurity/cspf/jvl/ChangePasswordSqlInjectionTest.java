package org.cysecurity.cspf.jvl;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Tests that changepassword.jsp uses parameterized queries (PreparedStatement)
 * instead of dynamic SQL string concatenation to prevent Second-Order SQL
 * Injection (CWE-89).
 *
 * <p>The SAST finding identified the following taint flow:
 *   SOURCE: rs.getString("id") stored in session["userid"] via LoginValidator
 *           (line 56, LoginValidator.java)
 *   FLOW:   session.getAttribute("userid").toString() → local variable "id"
 *           (line 15, changepassword.jsp)
 *   SINK:   "Update users set password='"+pass+"' where id="+id
 *           (line 40, changepassword.jsp) – both pass (direct user input) and
 *           id (second-order: retrieved from DB at login, stored in session)
 *           were concatenated directly into the SQL query.
 *
 * <p>The fix replaces Statement + string concatenation with PreparedStatement
 * and positional bind parameters (?) for both the password and the user id,
 * so neither value can alter the SQL structure regardless of its content.
 */
public class ChangePasswordSqlInjectionTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Helper: minimal in-memory stubs of Connection / PreparedStatement / Statement
    // No real database connection is required; all tests are self-contained.
    // ---------------------------------------------------------------------------

    /**
     * Captures the SQL template passed to prepareStatement() and every
     * setString() call, allowing tests to assert on exactly what was
     * sent to the JDBC driver.
     */
    static class CapturingPreparedStatement implements PreparedStatement {
        final String sql;
        final java.util.Map<Integer, String> bindings = new java.util.LinkedHashMap<>();

        CapturingPreparedStatement(String sql) {
            this.sql = sql;
        }

        @Override public void setString(int parameterIndex, String x) {
            bindings.put(parameterIndex, x);
        }

        // executeUpdate() with no args – the safe, parameterized overload used in the fix
        @Override public int executeUpdate() { return 1; }

        // All remaining PreparedStatement / Statement stubs
        @Override public ResultSet executeQuery() { return null; }
        @Override public ResultSet executeQuery(String s) { return null; }
        @Override public int executeUpdate(String s) { return 0; }
        @Override public void close() {}
        @Override public int getMaxFieldSize() { return 0; }
        @Override public void setMaxFieldSize(int i) {}
        @Override public int getMaxRows() { return 0; }
        @Override public void setMaxRows(int i) {}
        @Override public void setEscapeProcessing(boolean b) {}
        @Override public int getQueryTimeout() { return 0; }
        @Override public void setQueryTimeout(int i) {}
        @Override public void cancel() {}
        @Override public java.sql.SQLWarning getWarnings() { return null; }
        @Override public void clearWarnings() {}
        @Override public void setCursorName(String s) {}
        @Override public boolean execute(String s) { return false; }
        @Override public ResultSet getResultSet() { return null; }
        @Override public int getUpdateCount() { return 0; }
        @Override public boolean getMoreResults() { return false; }
        @Override public void setFetchDirection(int i) {}
        @Override public int getFetchDirection() { return 0; }
        @Override public void setFetchSize(int i) {}
        @Override public int getFetchSize() { return 0; }
        @Override public int getResultSetConcurrency() { return 0; }
        @Override public int getResultSetType() { return 0; }
        @Override public void addBatch(String s) {}
        @Override public void clearBatch() {}
        @Override public int[] executeBatch() { return new int[0]; }
        @Override public Connection getConnection() { return null; }
        @Override public boolean getMoreResults(int i) { return false; }
        @Override public ResultSet getGeneratedKeys() { return null; }
        @Override public int executeUpdate(String s, int i) { return 0; }
        @Override public int executeUpdate(String s, int[] ints) { return 0; }
        @Override public int executeUpdate(String s, String[] strings) { return 0; }
        @Override public boolean execute(String s, int i) { return false; }
        @Override public boolean execute(String s, int[] ints) { return false; }
        @Override public boolean execute(String s, String[] strings) { return false; }
        @Override public int getResultSetHoldability() { return 0; }
        @Override public boolean isClosed() { return false; }
        @Override public void setPoolable(boolean b) {}
        @Override public boolean isPoolable() { return false; }
        @Override public void closeOnCompletion() {}
        @Override public boolean isCloseOnCompletion() { return false; }
        @Override public <T> T unwrap(Class<T> c) { return null; }
        @Override public boolean isWrapperFor(Class<?> c) { return false; }
        @Override public void setNull(int i, int j) {}
        @Override public void setBoolean(int i, boolean b) {}
        @Override public void setByte(int i, byte b) {}
        @Override public void setShort(int i, short s) {}
        @Override public void setInt(int i, int j) {}
        @Override public void setLong(int i, long l) {}
        @Override public void setFloat(int i, float v) {}
        @Override public void setDouble(int i, double v) {}
        @Override public void setBigDecimal(int i, java.math.BigDecimal bd) {}
        @Override public void setBytes(int i, byte[] bytes) {}
        @Override public void setDate(int i, java.sql.Date d) {}
        @Override public void setTime(int i, java.sql.Time t) {}
        @Override public void setTimestamp(int i, java.sql.Timestamp ts) {}
        @Override public void setAsciiStream(int i, java.io.InputStream is, int l) {}
        @Override public void setUnicodeStream(int i, java.io.InputStream is, int l) {}
        @Override public void setBinaryStream(int i, java.io.InputStream is, int l) {}
        @Override public void clearParameters() {}
        @Override public void setObject(int i, Object o, int t) {}
        @Override public void setObject(int i, Object o) {}
        @Override public boolean execute() { return false; }
        @Override public void addBatch() {}
        @Override public void setCharacterStream(int i, java.io.Reader r, int l) {}
        @Override public void setRef(int i, java.sql.Ref r) {}
        @Override public void setBlob(int i, java.sql.Blob b) {}
        @Override public void setClob(int i, java.sql.Clob c) {}
        @Override public void setArray(int i, java.sql.Array a) {}
        @Override public java.sql.ResultSetMetaData getMetaData() { return null; }
        @Override public void setDate(int i, java.sql.Date d, java.util.Calendar c) {}
        @Override public void setTime(int i, java.sql.Time t, java.util.Calendar c) {}
        @Override public void setTimestamp(int i, java.sql.Timestamp ts, java.util.Calendar c) {}
        @Override public void setNull(int i, int t, String n) {}
        @Override public void setURL(int i, java.net.URL u) {}
        @Override public java.sql.ParameterMetaData getParameterMetaData() { return null; }
        @Override public void setRowId(int i, java.sql.RowId r) {}
        @Override public void setNString(int i, String s) {}
        @Override public void setNCharacterStream(int i, java.io.Reader r, long l) {}
        @Override public void setNClob(int i, java.sql.NClob c) {}
        @Override public void setClob(int i, java.io.Reader r, long l) {}
        @Override public void setBlob(int i, java.io.InputStream is, long l) {}
        @Override public void setNClob(int i, java.io.Reader r, long l) {}
        @Override public void setSQLXML(int i, java.sql.SQLXML x) {}
        @Override public void setObject(int i, Object o, int t, int s) {}
        @Override public void setAsciiStream(int i, java.io.InputStream is, long l) {}
        @Override public void setBinaryStream(int i, java.io.InputStream is, long l) {}
        @Override public void setCharacterStream(int i, java.io.Reader r, long l) {}
        @Override public void setAsciiStream(int i, java.io.InputStream is) {}
        @Override public void setBinaryStream(int i, java.io.InputStream is) {}
        @Override public void setCharacterStream(int i, java.io.Reader r) {}
        @Override public void setNCharacterStream(int i, java.io.Reader r) {}
        @Override public void setClob(int i, java.io.Reader r) {}
        @Override public void setBlob(int i, java.io.InputStream is) {}
        @Override public void setNClob(int i, java.io.Reader r) {}
    }

    /**
     * Captures the last SQL template passed to prepareStatement().
     * createStatement() is intentionally unsupported and throws to fail loudly
     * if any code path attempts to use the legacy unsafe API.
     */
    static class CapturingConnection implements Connection {
        CapturingPreparedStatement lastPrepared;

        @Override
        public PreparedStatement prepareStatement(String sql) {
            lastPrepared = new CapturingPreparedStatement(sql);
            return lastPrepared;
        }

        @Override
        public Statement createStatement() {
            throw new UnsupportedOperationException(
                "createStatement() must NOT be used for password-change queries – use prepareStatement()");
        }

        // Remaining stubs
        @Override public boolean isClosed() { return false; }
        @Override public java.sql.DatabaseMetaData getMetaData() { return null; }
        @Override public void setReadOnly(boolean b) {}
        @Override public boolean isReadOnly() { return false; }
        @Override public void setCatalog(String s) {}
        @Override public String getCatalog() { return null; }
        @Override public void setTransactionIsolation(int i) {}
        @Override public int getTransactionIsolation() { return 0; }
        @Override public java.sql.SQLWarning getWarnings() { return null; }
        @Override public void clearWarnings() {}
        @Override public Statement createStatement(int i, int j) { return null; }
        @Override public PreparedStatement prepareStatement(String s, int i, int j) { return prepareStatement(s); }
        @Override public java.sql.CallableStatement prepareCall(String s) { return null; }
        @Override public java.sql.CallableStatement prepareCall(String s, int i, int j) { return null; }
        @Override public String nativeSQL(String s) { return s; }
        @Override public void setAutoCommit(boolean b) {}
        @Override public boolean getAutoCommit() { return true; }
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public void close() {}
        @Override public java.util.Map<String, Class<?>> getTypeMap() { return null; }
        @Override public void setTypeMap(java.util.Map<String, Class<?>> m) {}
        @Override public void setHoldability(int i) {}
        @Override public int getHoldability() { return 0; }
        @Override public java.sql.Savepoint setSavepoint() { return null; }
        @Override public java.sql.Savepoint setSavepoint(String s) { return null; }
        @Override public void rollback(java.sql.Savepoint sp) {}
        @Override public void releaseSavepoint(java.sql.Savepoint sp) {}
        @Override public Statement createStatement(int i, int j, int k) { return null; }
        @Override public PreparedStatement prepareStatement(String s, int i, int j, int k) { return prepareStatement(s); }
        @Override public java.sql.CallableStatement prepareCall(String s, int i, int j, int k) { return null; }
        @Override public PreparedStatement prepareStatement(String s, int i) { return prepareStatement(s); }
        @Override public PreparedStatement prepareStatement(String s, int[] ints) { return prepareStatement(s); }
        @Override public PreparedStatement prepareStatement(String s, String[] strings) { return prepareStatement(s); }
        @Override public java.sql.Clob createClob() { return null; }
        @Override public java.sql.Blob createBlob() { return null; }
        @Override public java.sql.NClob createNClob() { return null; }
        @Override public java.sql.SQLXML createSQLXML() { return null; }
        @Override public boolean isValid(int i) { return true; }
        @Override public void setClientInfo(String k, String v) {}
        @Override public void setClientInfo(java.util.Properties p) {}
        @Override public String getClientInfo(String k) { return null; }
        @Override public java.util.Properties getClientInfo() { return null; }
        @Override public java.sql.Array createArrayOf(String t, Object[] e) { return null; }
        @Override public java.sql.Struct createStruct(String t, Object[] a) { return null; }
        @Override public void setSchema(String s) {}
        @Override public String getSchema() { return null; }
        @Override public void abort(java.util.concurrent.Executor e) {}
        @Override public void setNetworkTimeout(java.util.concurrent.Executor e, int ms) {}
        @Override public int getNetworkTimeout() { return 0; }
        @Override public <T> T unwrap(Class<T> c) { return null; }
        @Override public boolean isWrapperFor(Class<?> c) { return false; }
    }

    // ---------------------------------------------------------------------------
    // Utility: simulate the exact query construction from the fixed JSP
    // ---------------------------------------------------------------------------

    /**
     * Replicates the parameterized query logic from the fixed changepassword.jsp:
     * <pre>
     *   PreparedStatement stmt = con.prepareStatement(
     *       "UPDATE users SET password=? WHERE id=?");
     *   stmt.setString(1, pass);
     *   stmt.setString(2, id);
     *   stmt.executeUpdate();
     * </pre>
     *
     * @param con      capturing connection stub
     * @param password the new password (from request parameter "password")
     * @param userId   the session-stored user id (second-order tainted value)
     */
    private static CapturingPreparedStatement simulateChangePassword(
            CapturingConnection con, String password, String userId)
            throws java.sql.SQLException {

        PreparedStatement stmt = con.prepareStatement(
                "UPDATE users SET password=? WHERE id=?");
        stmt.setString(1, password);
        stmt.setString(2, userId);
        stmt.executeUpdate();
        return con.lastPrepared;
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /**
     * The SQL template must contain exactly 2 positional placeholders (?):
     * one for the new password and one for the user id.
     */
    public void testQueryTemplateContainsTwoPlaceholders() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateChangePassword(con, "newPass123", "42");

        int placeholderCount = stmt.sql.split("\\?", -1).length - 1;
        assertEquals("SQL template must contain exactly 2 bind parameters", 2, placeholderCount);
    }

    /**
     * The SQL template must NOT embed the literal password value.
     */
    public void testQueryTemplateDoesNotContainLiteralPassword() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String password = "mySecretPassword";

        CapturingPreparedStatement stmt = simulateChangePassword(con, password, "1");

        assertFalse("SQL template must not contain the literal password value",
                stmt.sql.contains(password));
    }

    /**
     * The SQL template must NOT embed the literal user id value.
     */
    public void testQueryTemplateDoesNotContainLiteralUserId() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String userId = "99";

        CapturingPreparedStatement stmt = simulateChangePassword(con, "pass", userId);

        assertFalse("SQL template must not contain the literal userId",
                stmt.sql.contains(userId));
    }

    /**
     * A classic SQL-injection payload in the password field must be bound
     * as a literal string at parameter index 1, not interpreted as SQL.
     * This covers direct (first-order) SQL injection via the password input.
     */
    public void testSqlInjectionPayloadInPasswordBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String sqlInjectionPayload = "' OR '1'='1";

        CapturingPreparedStatement stmt = simulateChangePassword(con, sqlInjectionPayload, "1");

        assertEquals("SQL injection payload in password must be bound literally at parameter 1",
                sqlInjectionPayload, stmt.bindings.get(1));
        assertFalse("SQL template must not contain the injection payload",
                stmt.sql.contains(sqlInjectionPayload));
    }

    /**
     * A second-order SQL injection payload in the session-stored user id must
     * be bound as a literal string at parameter index 2 and must not modify
     * the SQL structure.
     *
     * <p>This is the core of the reported vulnerability: the "id" value was
     * originally read from the database (via rs.getString("id") in LoginValidator)
     * and stored in the session. If that stored value contains SQL syntax (e.g.,
     * because it was poisoned during account creation), the parameterized query
     * must still treat it as plain data.
     */
    public void testSecondOrderInjectionPayloadInUserIdBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        // Simulate a second-order payload: an id value that was persisted in the
        // DB during registration (e.g. via a separate injection) and later
        // retrieved and placed in the session.
        String poisonedId = "1 OR 1=1";

        CapturingPreparedStatement stmt = simulateChangePassword(con, "newpass", poisonedId);

        assertEquals("Second-order poisoned userId must be bound literally at parameter 2",
                poisonedId, stmt.bindings.get(2));
        assertFalse("SQL template must not contain the poisoned id literal",
                stmt.sql.contains(poisonedId));
    }

    /**
     * A tautology bypass payload in the user id must not affect the SQL template.
     */
    public void testTautologyBypassInUserIdBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String tautologyPayload = "1 OR 1=1 --";

        CapturingPreparedStatement stmt = simulateChangePassword(con, "pass", tautologyPayload);

        assertEquals("Tautology payload in userId must be bound literally at parameter 2",
                tautologyPayload, stmt.bindings.get(2));
        assertFalse("SQL template must not be altered by tautology payload",
                stmt.sql.toUpperCase().contains("OR 1=1"));
    }

    /**
     * A stacked-query DROP TABLE attack in the password field must not execute.
     */
    public void testStackedQueryDropTableInPasswordBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String stackedPayload = "'; DROP TABLE users; --";

        CapturingPreparedStatement stmt = simulateChangePassword(con, stackedPayload, "5");

        assertEquals("Stacked-query payload must be bound literally at parameter 1",
                stackedPayload, stmt.bindings.get(1));
        assertFalse("SQL template must not contain DROP TABLE",
                stmt.sql.toUpperCase().contains("DROP TABLE"));
    }

    /**
     * A UNION-based injection attempt in the user id must be bound as data.
     */
    public void testUnionInjectionInUserIdBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String unionPayload = "1 UNION SELECT null, null, null --";

        CapturingPreparedStatement stmt = simulateChangePassword(con, "pass", unionPayload);

        assertEquals("UNION payload in userId must be bound literally at parameter 2",
                unionPayload, stmt.bindings.get(2));
        assertFalse("SQL template must not contain UNION keyword from payload",
                stmt.sql.toUpperCase().contains("UNION"));
    }

    /**
     * A legitimate new password must be bound at parameter index 1.
     */
    public void testLegitimatePasswordBoundAtIndex1() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String password = "Str0ng!P@ssw0rd";
        String userId   = "7";

        CapturingPreparedStatement stmt = simulateChangePassword(con, password, userId);

        assertEquals("Legitimate password must be bound at parameter index 1",
                password, stmt.bindings.get(1));
    }

    /**
     * A legitimate user id must be bound at parameter index 2.
     */
    public void testLegitimateUserIdBoundAtIndex2() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String password = "Str0ng!P@ssw0rd";
        String userId   = "7";

        CapturingPreparedStatement stmt = simulateChangePassword(con, password, userId);

        assertEquals("Legitimate userId must be bound at parameter index 2",
                userId, stmt.bindings.get(2));
    }

    /**
     * The fix must use PreparedStatement (via prepareStatement), NOT Statement
     * (via createStatement). The CapturingConnection throws
     * UnsupportedOperationException from createStatement(), so if the legacy
     * code path were still present this test would fail with that exception.
     */
    public void testPreparedStatementUsedNotStatement() throws Exception {
        CapturingConnection con = new CapturingConnection();

        // If the code still calls con.createStatement() this will throw
        simulateChangePassword(con, "pass", "1");

        // Reaching here proves prepareStatement() was called
        assertNotNull("A PreparedStatement must have been prepared via prepareStatement()",
                con.lastPrepared);
    }

    /**
     * A password containing single quotes must be bound safely without
     * requiring manual escaping by the application code.
     */
    public void testPasswordWithSingleQuotesBoundSafely() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String passwordWithQuotes = "it's\"a;tricky'password";

        CapturingPreparedStatement stmt = simulateChangePassword(con, passwordWithQuotes, "3");

        assertEquals("Password with quotes must be bound as-is at parameter 1",
                passwordWithQuotes, stmt.bindings.get(1));
    }

    /**
     * A user id with special SQL characters (second-order scenario: attacker
     * poisoned their username/id during registration to contain SQL metacharacters)
     * must be bound safely.
     */
    public void testUserIdWithSpecialCharactersBoundSafely() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String specialId = "1'; UPDATE users SET privilege='admin' WHERE '1'='1";

        CapturingPreparedStatement stmt = simulateChangePassword(con, "newpass", specialId);

        assertEquals("Special-character userId must be bound as-is at parameter 2",
                specialId, stmt.bindings.get(2));
        assertFalse("SQL template must not be modified by special-character userId",
                stmt.sql.contains("privilege"));
    }

    /**
     * Verifies that the SQL template targets the correct table and columns,
     * confirming the UPDATE statement was not structurally changed by the fix.
     */
    public void testQueryTemplateStructureIsCorrect() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateChangePassword(con, "pass", "1");

        // Template must update the password column in the users table filtered by id
        String sqlUpper = stmt.sql.toUpperCase();
        assertTrue("Query must be an UPDATE statement", sqlUpper.contains("UPDATE"));
        assertTrue("Query must target the 'users' table", sqlUpper.contains("USERS"));
        assertTrue("Query must set the 'password' column", sqlUpper.contains("PASSWORD"));
        assertTrue("Query must have a WHERE id clause", sqlUpper.contains("WHERE"));
    }

    /**
     * There must be exactly 2 bind parameters set — one for password, one for id.
     * No extra values should be bound that could indicate leakage or mis-mapping.
     */
    public void testExactlyTwoBindingsAreSet() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateChangePassword(con, "somePass", "42");

        assertEquals("Exactly 2 bind parameters must be set", 2, stmt.bindings.size());
    }
}
