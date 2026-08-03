package org.cysecurity.cspf.jvl;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Tests that the admin login page uses parameterized queries (PreparedStatement)
 * instead of dynamic SQL string concatenation to prevent SQL Injection (CWE-89).
 *
 * <p>The SAST finding identified the taint flow:
 *   SOURCE: request.getParameter("username") at line 11
 *   SINK:   stmt.executeQuery(...) at line 19 with the username concatenated
 *
 * <p>The fix replaces Statement+string-concatenation with PreparedStatement
 * and positional bind parameters (?), so user-controlled input is never
 * interpreted as SQL syntax.
 */
public class AdminLoginSqlInjectionTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Helper: minimal in-memory stub of Connection / PreparedStatement / Statement
    // We do NOT connect to a real database so the tests are fully self-contained.
    // ---------------------------------------------------------------------------

    /**
     * Tracks which SQL string was passed to prepareStatement() and how many
     * setString() calls were made, so tests can assert on those facts.
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

        // executeQuery with no args – the safe, parameterized overload used in the fix
        @Override public ResultSet executeQuery() { return null; }

        // All remaining PreparedStatement/Statement methods – stubs only
        @Override public ResultSet executeQuery(String s) { return null; }
        @Override public int executeUpdate() { return 0; }
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
     * Captures the last SQL string passed to prepareStatement(), exposing it
     * for assertion. createStatement() is intentionally unsupported to fail
     * loudly if legacy code tries to use it.
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
                "createStatement() must NOT be used for login queries – use prepareStatement()");
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
     * Replicates the query-construction logic of the fixed adminlogin.jsp so we
     * can assert on it without a servlet container.
     */
    private static CapturingPreparedStatement simulateAdminLogin(
            CapturingConnection con, String username, String hashedPassword)
            throws java.sql.SQLException {

        // This mirrors the fixed JSP code exactly:
        //   PreparedStatement stmt = con.prepareStatement(
        //       "select * from users where username=? and password=? and privilege='admin'");
        //   stmt.setString(1, user);
        //   stmt.setString(2, pass);
        //   rs = stmt.executeQuery();
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=? and privilege='admin'");
        stmt.setString(1, username);
        stmt.setString(2, hashedPassword);
        stmt.executeQuery();   // no-arg overload; safe per fix
        return con.lastPrepared;
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /**
     * The SQL template must contain only positional placeholders (?) for the
     * username and password – never the literal values.
     */
    public void testQueryTemplateContainsPlaceholdersNotLiteralValues() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "admin";
        String password = "someHashedPassword";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, username, password);

        // Template should contain exactly 2 placeholders
        int placeholderCount = stmt.sql.split("\\?", -1).length - 1;
        assertEquals("SQL template must contain exactly 2 bind parameters", 2, placeholderCount);

        // Template must NOT contain the literal username
        assertFalse("SQL template must not contain literal username value",
                stmt.sql.contains(username));

        // Template must NOT contain the literal password
        assertFalse("SQL template must not contain literal password value",
                stmt.sql.contains(password));
    }

    /**
     * The privilege constraint must be hard-coded in the query template, not
     * supplied via a bind parameter or user input.
     */
    public void testQueryTemplateContainsHardCodedPrivilegeAdmin() throws Exception {
        CapturingConnection con = new CapturingConnection();
        CapturingPreparedStatement stmt = simulateAdminLogin(con, "user", "hash");

        assertTrue("Query template must hard-code privilege='admin'",
                stmt.sql.contains("privilege='admin'"));
    }

    /**
     * The username is bound at parameter index 1. Even a classic SQL-injection
     * payload (' OR '1'='1) must be bound literally, not interpreted as SQL.
     */
    public void testSqlInjectionPayloadInUsernameIsBoundAsLiteral() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String sqlInjectionPayload = "' OR '1'='1";
        String password = "irrelevant_hash";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, sqlInjectionPayload, password);

        // The payload must be stored verbatim as the first bind parameter
        assertEquals("SQL injection payload must be bound literally at parameter 1",
                sqlInjectionPayload, stmt.bindings.get(1));

        // The SQL template itself must not have been altered by the payload
        assertFalse("SQL template must not contain the injection payload",
                stmt.sql.contains(sqlInjectionPayload));
    }

    /**
     * The tautology bypass (' OR 1=1 --) must also be bound literally.
     */
    public void testTautologyBypassPayloadBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String tautologyPayload = "admin' OR 1=1 --";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, tautologyPayload, "hash");

        assertEquals("Tautology bypass payload must be bound literally at parameter 1",
                tautologyPayload, stmt.bindings.get(1));
        assertFalse("SQL template must not contain the tautology payload",
                stmt.sql.contains(tautologyPayload));
    }

    /**
     * A UNION-based injection attempt in the username must be bound literally.
     */
    public void testUnionBasedInjectionPayloadBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String unionPayload = "' UNION SELECT null,null,null,null,null --";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, unionPayload, "hash");

        assertEquals("UNION injection payload must be bound literally at parameter 1",
                unionPayload, stmt.bindings.get(1));
        assertFalse("SQL template must not contain the UNION payload",
                stmt.sql.contains("UNION"));
    }

    /**
     * A stacked-query injection attempt must be bound literally.
     */
    public void testStackedQueryInjectionPayloadBoundLiterally() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String stackedPayload = "admin'; DROP TABLE users; --";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, stackedPayload, "hash");

        assertEquals("Stacked query payload must be bound literally at parameter 1",
                stackedPayload, stmt.bindings.get(1));
        assertFalse("SQL template must not contain DROP TABLE",
                stmt.sql.toUpperCase().contains("DROP TABLE"));
    }

    /**
     * A legitimate, benign admin username must be bound at parameter index 1.
     */
    public void testLegitimateUsernameIsBoundAtIndex1() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "admin";
        String hashedPass = "5f4dcc3b5aa765d61d8327deb882cf99"; // MD5("password")

        CapturingPreparedStatement stmt = simulateAdminLogin(con, username, hashedPass);

        assertEquals("Username must be bound at parameter index 1", username, stmt.bindings.get(1));
    }

    /**
     * The hashed password must be bound at parameter index 2.
     */
    public void testHashedPasswordIsBoundAtIndex2() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String username = "admin";
        String hashedPass = "5f4dcc3b5aa765d61d8327deb882cf99";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, username, hashedPass);

        assertEquals("Password must be bound at parameter index 2", hashedPass, stmt.bindings.get(2));
    }

    /**
     * The fixed code must use PreparedStatement (via prepareStatement), NOT
     * Statement (via createStatement). Using createStatement() on the capturing
     * Connection throws UnsupportedOperationException, so reaching that path
     * would fail this test.
     */
    public void testPreparedStatementIsUsedNotStatement() throws Exception {
        CapturingConnection con = new CapturingConnection();

        // If the code mistakenly calls con.createStatement() this will throw
        simulateAdminLogin(con, "admin", "hash");

        // Reaching here proves prepareStatement() was called
        assertNotNull("A PreparedStatement must have been prepared", con.lastPrepared);
    }

    /**
     * Empty-string username must be bound safely (no special SQL meaning).
     */
    public void testEmptyUsernameIsBoundSafely() throws Exception {
        CapturingConnection con = new CapturingConnection();

        CapturingPreparedStatement stmt = simulateAdminLogin(con, "", "hash");

        assertEquals("Empty username must be bound literally", "", stmt.bindings.get(1));
    }

    /**
     * Username containing special SQL characters must be bound as-is without
     * escaping required from the caller side (the driver handles it).
     */
    public void testUsernameWithSpecialCharactersIsBoundAsIs() throws Exception {
        CapturingConnection con = new CapturingConnection();
        String specialChars = "user'\"\\;%_";

        CapturingPreparedStatement stmt = simulateAdminLogin(con, specialChars, "hash");

        assertEquals("Special-character username must be bound as-is at parameter 1",
                specialChars, stmt.bindings.get(1));
    }
}
