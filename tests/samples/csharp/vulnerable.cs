using System;
using System.Data.SqlClient;
using System.Web;
using System.Diagnostics;

public class VulnerableController
{
    public void Search()
    {
        var request = HttpContext.Current.Request;
        string userInput = request.QueryString["q"];
        string password = "admin123";

        string query = "SELECT * FROM items WHERE name = '" + userInput + "'";
        using (var conn = new SqlConnection("connstr"))
        {
            var cmd = new SqlCommand(query, conn);
            conn.Open();
            cmd.ExecuteNonQuery();
        }

        var process = new Process();
        process.StartInfo.FileName = "cmd.exe";
        process.StartInfo.Arguments = "/c dir " + userInput;
        process.Start();

        HttpContext.Current.Response.Redirect(userInput);

        HttpContext.Current.Response.Write("<p>Hello, " + userInput + "</p>");
    }
}
