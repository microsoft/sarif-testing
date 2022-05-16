using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using System.Text.RegularExpressions;

namespace VulnerableWebService.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class DatastoreController : ControllerBase
    {
        private readonly ILogger<DatastoreController> logger;

        public DatastoreController(ILogger<DatastoreController> logger)
        {
            this.logger = logger;
        }

        [HttpGet]
        public string GetFileContents(string path)
        {
            logger.LogInformation($"Getting contents of file '{path}' for user '{HttpContext.Request.Query["username"]}'");
            return System.IO.File.Exists(path) ? System.IO.File.ReadAllText(path) : null;
        }

        public string GetDataValue(string token)
        {
            string data = "some-data";
            Match match = Regex.Match(data, "^term=" + Regex.Escape(token));

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
