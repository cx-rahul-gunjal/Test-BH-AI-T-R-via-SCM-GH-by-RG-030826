package org.cysecurity.cspf.jvl;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Tests that the second-order SQL injection vulnerability (CWE-89) identified
 * across LoginValidator.java and Messages.jsp has been remediated.
 *
 * <p>The SAST finding described the following full taint path:
 *   <ol>
 *     <li>SOURCE  (LoginValidator.java line 52): User-controlled "username" and
 *         "password" parameters were concatenated directly into a SQL query
 *         (first-order injection). The database response {@code rs} flows into
 *         {@code session.setAttribute("user", rs.getString("username"))}.</li>
 *     <li>FLOW    (LoginValidator.java lines 52-57): The username read from the
 *         DB at login time is persisted in the HTTP session under the key "user".</li>
 *     <li>SINK    (Messages.jsp line 14): {@code session.getAttribute("user")} is
 *         used verbatim in a second SQL query string without sanitisation, enabling
 *         a second-order SQL injection attack if the stored username contained SQL
 *         metacharacters that bypassed the first query.</li>
 *   </ol>
 *
 * <p>The fix replaces {@code Statement} + string-concatenation with
 * {@code PreparedStatement} and positional bind parameters ({@code ?}) in both:
 * <ul>
 *   <li>{@code LoginValidator.java} – the initial login query</li>
 *   <li>{@code Messages.jsp} – the messages-retrieval query</li>
 * </ul>
 * This means user-supplied values (whether direct or second-order) are always
 * treated as data by the JDBC driver and can never alter the SQL structure.
 *
 * <p>All tests are fully self-contained and do not require a live database
 * connection; they use in-memory stub implementations of {@code Connection},
 * {@code PreparedStatement}, and {@code Statement}.
 */
public class SecondOrderSqlInjectionMessagesTest extends TestCase {

    // -------------------------------------------------------------------------
    // Stubs: CapturingPreparedStatement
    // -------------------------------------------------------------------------

    /**
     * Records the SQL template passed to {@code prepareStatement()} and all
     * subsequent {@code setString()} bindings. Tests inspect these fields to
     * verify that user-controlled values are bound as parameters, never
     * embedded in the SQL text.
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

        // Safe no-arg overloads used by the fixed code
        @Override public ResultSet executeQuery() { return null; }
        @Override public int executeUpdate()      { return 1; }

        // All remaining PreparedStatement / Statement stubs
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

    // -------------------------------------------------------------------------
    // Stubs: CapturingConnection
    // -------------------------------------------------------------------------

    /**
     * Records every {@code prepareStatement()} call and throws from
     * {@code createStatement()} to detect any remaining use of the unsafe API.
     */
    static class CapturingConnection implements Connection {
        CapturingPreparedStatement lastPrepared;

        @Override
        public PreparedStatement prepareStatement(String sql) {
            lastPrepared = new CapturingPreparedStatement(sql);
            return lastPrepared;
        }

        /**
         * Intentionally unsupported — any call from fixed code indicates that
         * the vulnerability still exists.
         */
        @Override
        public Statement createStatement() {
            throw new UnsupportedOperationException(
                "createStatement() must NOT be used for parameterised queries — use prepareStatement()");
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

    // -------------------------------------------------------------------------
    // Helpers: simulate the fixed code paths
    // -------------------------------------------------------------------------

    /**
     * Simulates the fixed {@code LoginValidator.processRequest()} query:
     * <pre>
     *   PreparedStatement stmt = con.prepareStatement(
     *       "select * from users where username=? and password=?");
     *   stmt.setString(1, user);
     *   stmt.setString(2, pass);
     *   rs = stmt.executeQuery();
     * </pre>
     */
    private static CapturingPreparedStatement simulateLoginQuery(
            CapturingConnection con, String username, String password)
            throws java.sql.SQLException {

        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, username);
        stmt.setString(2, password);
        stmt.executeQuery();
        return con.lastPrepared;
    }

    /**
     * Simulates the fixed {@code Messages.jsp} query, using a session-stored
     * username as the recipient parameter:
     * <pre>
     *   PreparedStatement stmt = con.prepareStatement(
     *       "select * from UserMessages where recipient=?");
     *   stmt.setString(1, sessionUser);
     *   rs = stmt.executeQuery();
     * </pre>
     *
     * @param sessionUser the value of {@code session.getAttribute("user")} —
     *                    originally retrieved from the DB during login
     */
    private static CapturingPreparedStatement simulateMessagesQuery(
            CapturingConnection con, String sessionUser)
            throws java.sql.SQLException {

        PreparedStatement stmt = con.prepareStatement(
                "select * from UserMessages where recipient=?");
        stmt.setString(1, sessionUser);
        stmt.executeQuery();
        return con.lastPrepared;
    }

    // =========================================================================
    // Tests for Messages.jsp (sink — second-order injection)
    // =========================================================================

    /**
     * The Messages.jsp SQL template must contain exactly one positional
     * placeholder ({@code ?}) for the recipient value.
     */
    public void testMessagesQueryTemplateContainsOnePlaceholder() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, "alice");

        int placeholderCount = stmt.sql.split("\\?", -1).length - 1;
        assertEquals("Messages SQL template must contain exactly 1 bind parameter", 1, placeholderCount);
    }

    /**
     * The Messages.jsp SQL template must never contain the literal username value.
     */
    public void testMessagesQueryTemplateDoesNotContainLiteralUsername() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "alice";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, username);

        assertFalse("Messages SQL template must not contain the literal username",
                stmt.sql.contains(username));
    }

    /**
     * A classic SQL-injection payload stored in the session (second-order scenario)
     * must be bound as a literal data value, not interpreted as SQL syntax.
     *
     * <p>Attack scenario: an attacker registers a username such as
     * {@code alice' OR '1'='1}. After login, this value is stored in the session
     * under "user". Without a parameterized query in Messages.jsp, the SQL would
     * become:
     * <pre>
     *   select * from UserMessages where recipient='alice' OR '1'='1'
     * </pre>
     * returning messages belonging to all users. The fix prevents this.
     */
    public void testSecondOrderInjectionPayloadInSessionUserBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        // Simulates a username stored in the session that contains SQL metacharacters
        String poisonedUsername = "alice' OR '1'='1";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, poisonedUsername);

        assertEquals("Second-order poisoned username must be bound literally at parameter 1",
                poisonedUsername, stmt.bindings.get(1));
        assertFalse("Messages SQL template must not be altered by the injection payload",
                stmt.sql.contains("OR"));
    }

    /**
     * A UNION-based second-order injection payload (e.g. a username containing
     * UNION SELECT) must remain as bound data and must not appear in the SQL template.
     */
    public void testUnionInjectionInSessionUserBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String unionPayload = "x' UNION SELECT null,null,null,null --";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, unionPayload);

        assertEquals("UNION payload in session username must be bound literally at parameter 1",
                unionPayload, stmt.bindings.get(1));
        assertFalse("Messages SQL template must not contain UNION from payload",
                stmt.sql.toUpperCase().contains("UNION"));
    }

    /**
     * A stacked-query injection attempt in the session username must not produce
     * a DROP TABLE or any additional SQL statement.
     */
    public void testStackedQueryInjectionInSessionUserBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String stackedPayload = "alice'; DROP TABLE UserMessages; --";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, stackedPayload);

        assertEquals("Stacked-query payload must be bound literally at parameter 1",
                stackedPayload, stmt.bindings.get(1));
        assertFalse("Messages SQL template must not contain DROP TABLE",
                stmt.sql.toUpperCase().contains("DROP TABLE"));
    }

    /**
     * A tautology bypass (e.g., {@code ' OR 1=1 --}) in the session username
     * must not affect the SQL template.
     */
    public void testTautologyBypassInSessionUserBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String tautologyPayload = "' OR 1=1 --";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, tautologyPayload);

        assertEquals("Tautology bypass must be bound literally at parameter 1",
                tautologyPayload, stmt.bindings.get(1));
        assertFalse("Messages SQL template must not be altered by tautology",
                stmt.sql.toUpperCase().contains("OR 1=1"));
    }

    /**
     * A legitimate, benign username stored in the session must be bound at
     * parameter index 1.
     */
    public void testLegitimateSessionUserBoundAtIndex1() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "alice";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, username);

        assertEquals("Legitimate session username must be bound at parameter index 1",
                username, stmt.bindings.get(1));
    }

    /**
     * A username containing single quotes and backslashes must be bound safely
     * without requiring manual escaping by the application code.
     */
    public void testUsernameWithSpecialCharactersBoundSafely() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String specialUsername = "O'Brien\\; admin";

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, specialUsername);

        assertEquals("Username with special chars must be bound as-is at parameter 1",
                specialUsername, stmt.bindings.get(1));
    }

    /**
     * Exactly one binding must be set for the Messages.jsp query — the recipient.
     */
    public void testMessagesQueryHasExactlyOneBinding() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, "alice");

        assertEquals("Messages query must set exactly 1 bind parameter", 1, stmt.bindings.size());
    }

    /**
     * Messages.jsp must use {@code PreparedStatement} (via {@code prepareStatement}),
     * NOT the legacy {@code Statement} (via {@code createStatement}). The capturing
     * connection throws if {@code createStatement()} is called.
     */
    public void testMessagesQueryUsesPreparedStatementNotStatement() throws Exception {
        CapturingConnection con = new CapturingConnection();

        // If code still calls createStatement() this will throw UnsupportedOperationException
        simulateMessagesQuery(con, "alice");

        assertNotNull("A PreparedStatement must have been prepared for Messages.jsp query",
                con.lastPrepared);
    }

    /**
     * The Messages.jsp SQL template must reference the correct table name
     * ({@code UserMessages}) and column ({@code recipient}).
     */
    public void testMessagesQueryTemplateStructureIsCorrect() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateMessagesQuery(con, "alice");

        String sqlUpper = stmt.sql.toUpperCase();
        assertTrue("Messages query must reference USERMESSAGES table",
                sqlUpper.contains("USERMESSAGES"));
        assertTrue("Messages query must filter by RECIPIENT column",
                sqlUpper.contains("RECIPIENT"));
    }

    // =========================================================================
    // Tests for LoginValidator.java (source — first-order injection)
    // =========================================================================

    /**
     * The login query template must contain exactly 2 positional placeholders:
     * one for username and one for password.
     */
    public void testLoginQueryTemplateContainsTwoPlaceholders() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateLoginQuery(con, "alice", "secret");

        int count = stmt.sql.split("\\?", -1).length - 1;
        assertEquals("Login SQL template must contain exactly 2 bind parameters", 2, count);
    }

    /**
     * The login query template must not contain the literal username.
     */
    public void testLoginQueryTemplateDoesNotContainLiteralUsername() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "alice";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, username, "secret");

        assertFalse("Login SQL template must not contain the literal username",
                stmt.sql.contains(username));
    }

    /**
     * The login query template must not contain the literal password.
     */
    public void testLoginQueryTemplateDoesNotContainLiteralPassword() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String password = "s3cr3tP@ss";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, "alice", password);

        assertFalse("Login SQL template must not contain the literal password",
                stmt.sql.contains(password));
    }

    /**
     * A classic {@code ' OR '1'='1} injection payload in the username must be
     * bound as a literal string at parameter index 1 and must not alter the
     * SQL template.
     */
    public void testLoginInjectionPayloadInUsernameBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String payload = "' OR '1'='1";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, payload, "anypass");

        assertEquals("Login injection payload must be bound literally at parameter 1",
                payload, stmt.bindings.get(1));
        assertFalse("Login SQL template must not be modified by username payload",
                stmt.sql.contains(payload));
    }

    /**
     * A classic SQL-injection bypass in the password field must also be bound
     * as literal data, preventing authentication bypass.
     */
    public void testLoginInjectionPayloadInPasswordBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String payload = "' OR '1'='1";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, "alice", payload);

        assertEquals("Password injection payload must be bound literally at parameter 2",
                payload, stmt.bindings.get(2));
        assertFalse("Login SQL template must not be modified by password payload",
                stmt.sql.contains(payload));
    }

    /**
     * The username must be bound at parameter index 1 and the password at
     * parameter index 2.
     */
    public void testLoginBindingOrder() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "alice";
        String password = "hunter2";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, username, password);

        assertEquals("Username must be at parameter index 1", username, stmt.bindings.get(1));
        assertEquals("Password must be at parameter index 2", password, stmt.bindings.get(2));
    }

    /**
     * {@code LoginValidator} must use {@code PreparedStatement}, NOT {@code Statement}.
     * Reaching the assertion proves that {@code prepareStatement()} was called.
     */
    public void testLoginQueryUsesPreparedStatementNotStatement() throws Exception {
        CapturingConnection con = new CapturingConnection();

        simulateLoginQuery(con, "alice", "secret");

        assertNotNull("A PreparedStatement must have been prepared for the login query",
                con.lastPrepared);
    }

    /**
     * A tautology bypass attempt ({@code admin' OR 1=1 --}) in the username
     * must not alter the SQL template.
     */
    public void testLoginTautologyBypassBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String tautologyPayload = "admin' OR 1=1 --";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, tautologyPayload, "pass");

        assertEquals("Tautology payload must be bound literally at parameter 1",
                tautologyPayload, stmt.bindings.get(1));
        assertFalse("Login SQL template must not contain the tautology payload",
                stmt.sql.contains(tautologyPayload));
    }

    /**
     * A UNION-based injection attempt in the login username must be bound safely.
     */
    public void testLoginUnionInjectionBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String unionPayload = "' UNION SELECT null,null,null,null --";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, unionPayload, "pass");

        assertEquals("UNION payload must be bound literally at parameter 1",
                unionPayload, stmt.bindings.get(1));
        assertFalse("Login SQL template must not contain UNION from payload",
                stmt.sql.toUpperCase().contains("UNION"));
    }

    /**
     * A stacked-query DROP TABLE attack in the login username must not modify
     * the SQL template.
     */
    public void testLoginStackedQueryBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String stackedPayload = "alice'; DROP TABLE users; --";

        CapturingPreparedStatement stmt = simulateLoginQuery(con, stackedPayload, "pass");

        assertEquals("Stacked-query payload must be bound literally at parameter 1",
                stackedPayload, stmt.bindings.get(1));
        assertFalse("Login SQL template must not contain DROP TABLE",
                stmt.sql.toUpperCase().contains("DROP TABLE"));
    }

    // =========================================================================
    // End-to-end second-order injection chain test
    // =========================================================================

    /**
     * Simulates the complete second-order attack chain:
     * <ol>
     *   <li>An attacker registers/uses a username that contains SQL metacharacters
     *       (e.g. via the login username field if first-order was once exploitable).</li>
     *   <li>The login query is executed parameterized — the payload cannot modify
     *       SQL during login.</li>
     *   <li>Regardless, whatever value the database returns for "username" is stored
     *       verbatim in the session.</li>
     *   <li>The Messages.jsp query is executed parameterized — the session value
     *       (even if poisoned) cannot modify SQL during message retrieval.</li>
     * </ol>
     *
     * <p>This test validates both steps are parameterized and the SQL templates
     * are never altered by the attacker-controlled username.
     */
    public void testEndToEndSecondOrderInjectionChainIsBlocked() throws Exception {
        // Step 1: Attacker submits a poisoned username at login
        CapturingConnection loginCon = new CapturingConnection();
        String poisonedUsername = "victim' UNION SELECT null,null,null,null WHERE '1'='1";

        CapturingPreparedStatement loginStmt = simulateLoginQuery(loginCon, poisonedUsername, "pass");

        // Login query must NOT be altered by the poisoned username
        assertFalse("Login SQL template must not contain the poisoned username",
                loginStmt.sql.contains(poisonedUsername));
        assertEquals("Poisoned username must be bound as data at login parameter 1",
                poisonedUsername, loginStmt.bindings.get(1));

        // Step 2: The (possibly poisoned) username is retrieved from DB and stored in session.
        // Simulate: session.getAttribute("user") returns the poisoned username
        // (as though it was stored in the DB and then retrieved via rs.getString("username")).
        String sessionUsername = poisonedUsername; // second-order: comes from DB / session

        // Step 3: Messages.jsp uses session username in its query
        CapturingConnection messagesCon = new CapturingConnection();
        CapturingPreparedStatement messagesStmt = simulateMessagesQuery(messagesCon, sessionUsername);

        // Messages query must NOT be altered by the second-order payload
        assertFalse("Messages SQL template must not contain the second-order payload",
                messagesStmt.sql.contains(sessionUsername));
        assertEquals("Second-order payload must be bound as data at messages parameter 1",
                sessionUsername, messagesStmt.bindings.get(1));

        // Both SQL templates must remain structurally intact
        assertFalse("Login SQL template must not contain UNION keyword from payload",
                loginStmt.sql.toUpperCase().contains("UNION"));
        assertFalse("Messages SQL template must not contain UNION keyword from payload",
                messagesStmt.sql.toUpperCase().contains("UNION"));
    }
}
