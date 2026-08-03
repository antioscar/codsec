import java.sql.*;
import java.security.MessageDigest;
import java.io.*;
import java.net.URL;

public class Vulnerable {
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";
    private static final String DB_PASS = "admin123";

    public String getUser(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query).toString();
    }

    public void renderProfile(String userName) {
        String html = "<div>Welcome " + userName + "</div>";
        response.getWriter().write(html);
    }

    public void runCommand(String host) {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public byte[] loadFile(String filename) {
        return new File("/var/uploads/" + filename).readAllBytes();
    }

    public Object restoreState(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    public void executeCode(String code) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        engine.eval(code);
    }

    public void fetchRemote(String url) throws Exception {
        URL target = new URL(url);
        target.openConnection().getInputStream();
    }

    public String hashPassword(String pass) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(pass.getBytes());
        return bytesToHex(digest);
    }
}
