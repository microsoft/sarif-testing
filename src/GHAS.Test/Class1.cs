using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GHAS.Test
{
    public class Class1
    {
        void MyMethod()
        {
            string str = null;
            int length = str.Length;
            string str2 = null;
            int l = str2.Length;
            // Try again
        }

        void UselessMethod()
        {
            // A helpful comment! ghgfh
            string s = "abc";
            string str = null;
            int l = str.Length; // This should trigger a result
        }

        void AnotherMethod(string str)
        {
            // Do tha loopty loop
            for (int i = 0; i < 10; i++)
            {
                // This is smart.
                Console.WriteLine($"The length of {nameof(str)} is " + str.Length);
                str = str.Substring(0, str.Length - 1);
            }
        }
    }
}
