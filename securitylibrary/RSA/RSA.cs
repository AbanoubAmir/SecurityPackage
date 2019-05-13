using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //C= M^e mod n  (n=p*q)
            int n = (p * q);
            int initialVal = 1;
            for (int i = 0; i < e; ++i)
            {
                initialVal = (initialVal * M) % n;
            }
            return initialVal;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //M= c^d mod n (n=p*q) (d= modInverse(e,ON))
            int n = (p * q);
            int ON = (p - 1) * (q - 1);
            int d = modInverse(e, ON);
            int initialVal = 1;
            for (int i = 0; i < d; ++i)
            {
                initialVal = (initialVal * C) % n;
            }
            return initialVal;
        }
        static int modInverse(int a, int m)
        {
            int m0 = m;
            int y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                // q is quotient 
                int q = a / m;

                int t = m;

                // m is remainder now, process 
                // same as Euclid's algo 
                m = a % m;
                a = t;
                t = y;

                // Update x and y 
                y = x - q * y;
                x = t;
            }

            // Make x positive 
            if (x < 0)
                x += m0;

            return x;
        }

    }
}
