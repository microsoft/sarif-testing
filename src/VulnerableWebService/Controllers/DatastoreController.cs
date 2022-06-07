using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Text.RegularExpressions;

namespace VulnerableWebService.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class DatastoreController : ControllerBase
    {
        [HttpGet]
        public string GetFileContents(string path)
        {
            return System.IO.File.ReadAllText(path);
        }

        public string GetDataValue(string token)
        {
            string data = "some-data";
            Match match = Regex.Match(data, "^term=" + token);

            return match.Success ? match.Value : null;
        }

        public void DeleteRecord(string id)
        {
            string sql = $"DELETE FROM dbo.Product WHERE ID = '{id}'";

            using var conn = new SqlConnection("my-connection-string");
            using SqlCommand cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }
    }
}
