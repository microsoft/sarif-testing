using System;

namespace GHAS.Test
{
    public class Class1
    {
        void MyMethod()
        {
            string str = null;
        }

        void UselessMethod()
        {
            // A helpful comment! ghgfh
            string s = "abc";
            string str = null;
        }

        /// <summary>
        /// Doc comment
        /// </summary>
        /// <param name="str">String.</param>
        void AnotherMethod(string str)
        {
            // Do tha loopty loop
            for (int i = 0; i < 10; i++)
            {
                // This is smart.
                Console.WriteLine($"The length of {nameof(str)} is " + str.Length); // Test
                str = str.Substring(0, str.Length - 1);
            }
        }
    }
}
