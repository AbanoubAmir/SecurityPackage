using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string CT = "";
            
            for (int i = 0; i < plainText.Length; i++)
            {
                int var = plainText[i]-97;
                int index = (var + key) % 26;
                CT += (char)(index+97); 

            }

            return CT;
            
        }

        public string Decrypt(string cipherText, int key)
        {
            string PT = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                int var = cipherText[i] - 65;   
                int index = (var - key);
                if (index < 0)
                 index += 26;
                PT += (char)(index+97);
            }

            return PT;
        }

        public int Analyse(string plainText, string cipherText)
        {
                int p = plainText[0] - 96;
                int c = cipherText[0] - 64;
                 int key = c - p;
                if (key < 0)
                    key += 26;
            return key;     
        }
    }
}
