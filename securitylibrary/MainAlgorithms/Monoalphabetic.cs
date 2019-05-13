using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            bool[] freq =new bool[26];
            for (int i = 0; i < freq.Length; i++)
                freq[i] = false;
            string ciphertolLower = cipherText.ToLower();
            char[] ptarr = plainText.ToCharArray();
            char[] cipher = ciphertolLower.ToCharArray();
            char[] keyarr = new char[26];
            for (int i = 0; i < plainText.Length; i++)
            {
                keyarr[ptarr[i] - 97] = cipher[i];
                freq[cipher[i] - 97] = true;
            }
            for (int i = 0; i < keyarr.Length; i++)
            {
                if (keyarr[i] == '\0')
                {
                    for (int j = 0; j < freq.Length; j++)
                    {
                        if (!freq[j])
                        {
                            keyarr[i] = (char)(j + 97);
                            freq[j] = true;
                            break;
                        }
                    }
                }
            }

            return new string(keyarr);
        }

        public string Decrypt(string cipherText, string key)
        {
            string ciphertoLower = cipherText.ToLower();
            char[] cipherarr = ciphertoLower.ToCharArray();
            char[] keyarr = key.ToCharArray();
            char[] plainText = new char[cipherText.Length];
            char vari = '0';//bn7ut feh awl 7arf mn el cipher
            char output = 'a';
            
            
            for (int i = 0; i < cipherarr.Length; i++)
            {
                vari = cipherarr[i];
                int counter = 0;
                for (int j =0;j<key.Length;j++)
                {
                   
                    if (vari == keyarr[j])
                        break;
                    else
                        counter++;

                }
              
                plainText[i] = (char)((int)output + counter);
            }
            return new string(plainText);
        }

        public string Encrypt(string plainText, string key)
        {
            char[] keyarr = key.ToCharArray();
            char[] ptarr = plainText.ToCharArray();
            char[] cipher = new char[plainText.Length];
            char vari = '0' ;
            int index;
            for(int i =0;i<ptarr.Length;i++)
            {
                vari = ptarr[i];
                index = (vari - 97)%26;
                cipher[i] = keyarr[index];
            }
         

            return new string (cipher);
           // throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plaintext ="";
            string key = "etaoinsrhldcumfpgwybvkxjqz";
            char[] keyArr = key.ToCharArray();
            string cipherlower = cipher.ToLower();
            char[] cipherArr = cipherlower.ToCharArray();
            int[] freqarr = new int[26];
            char[] maparr = new char[26];


            for (int i =0;i<freqarr.Length;i++)
            {
                freqarr[i] = 0;  
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                freqarr[cipherArr[i]-97]++;
            }
            for (int i = 0; i < freqarr.Length; i++)
            {
                int mx = 0;
                int mp = 0 ; 
                for(int j =0; j < freqarr.Length; j++)
                {
                    if(mx < freqarr[j])
                    {
                        mx = freqarr[j];
                        mp = j ;
                    }
                    
                }
                freqarr[mp] = 0;
                maparr[mp] = key[i];

            }
            for (int i = 0; i<cipher.Length; i++)
            {
                plaintext += maparr[cipherArr[i] - 97]; 

            }
            return plaintext;
        }
    }
}
