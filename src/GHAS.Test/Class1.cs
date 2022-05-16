using System.IO;
using System.Text.RegularExpressions;

namespace GHAS.Test
{
    public class VulnerableCode
    {
        /*
        void MyMethod()
        {
            string str = null;
            int length = str.Length;
        }
        */

        void EmptyMethod()
        {
            // A helpful comment! ghgfh
            string s = "abc";
            string x = s;
        }

        public string ReadFileContents(string path)
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }

        public string GetDataValue(string token)
        {
            string data = "some-data";
            Match match = Regex.Match(data, "^term=" + token);

            return match.Success ? match.Value : null;
        }
    }
}
