using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        // string mainPlain = "0x0123456789ABCDEF";
        public override string Encrypt(string plainText, string key)
        {
            //PT = 0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
            //B1 = 0000 0001 0010 0011 0100 0101 0110 0111
            //B2 = 1000 1001 1010 1011 1100 1101 1110 1111
            //K = 00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001

            string PTbinary = HexStringToBinary(plainText.Substring(2));
            string b1 = "";
            string b2 = "";
            string C = "";
            string D = "";
            string Keybinary = HexStringToBinary(key.Substring(2));
            string keyIP = "";
            PTbinary = ValidateInputIP(PTbinary);
            for (int i = 0; i < 32; i++)
            {
                b1 += PTbinary[i];
                b2 += PTbinary[i + 32];
            }
          
            Keybinary = ValidateKeyPC1(Keybinary);
            for (int i = 0; i < 28; i++)
            {
                C += Keybinary[i];
                D += Keybinary[i + 28];
            }
            KeySchedular(ref C, ref D , b2, b1);
           
            return null;
        }
        private static readonly Dictionary<char, string> hexCharacterToBinary = new Dictionary<char, string> {
    { '0', "0000" },
    { '1', "0001" },
    { '2', "0010" },
    { '3', "0011" },
    { '4', "0100" },
    { '5', "0101" },
    { '6', "0110" },
    { '7', "0111" },
    { '8', "1000" },
    { '9', "1001" },
    { 'a', "1010" },
    { 'b', "1011" },
    { 'c', "1100" },
    { 'd', "1101" },
    { 'e', "1110" },
    { 'f', "1111" }
};
        public string HexStringToBinary(string text)
        {
            string result = "";
            foreach (char c in text)
            {
                // This will crash for non-hex characters. You might want to handle that differently.
                result += hexCharacterToBinary[char.ToLower(c)].ToString();
            }
            return result;
        }
        public int[] GeneratePC1()
        {
            int[] PC_1 ={
                           57,  49  , 41  , 33  ,  25  ,  17  , 9,
                           1 ,  58  , 50  , 42  ,  34  ,  26  , 18,
                           10,  2   , 59  , 51  ,  43  ,  35  , 27,
                           19,  11  ,  3  , 60  ,  52  ,  44  , 36,
                           63,  55  , 47  , 39  ,  31  ,  23  , 15,
                           7 ,  62  , 54  , 46  ,  38  ,  30  , 22,
                           14,   6  , 61  , 53  ,  45  ,  37  , 29,
                           21,  13  , 5  ,  28  ,  20   , 12  ,  4
            };


            return PC_1;
        }
        public int[] GenerateIP()
        {
            int[] IP ={
            58  ,  50 ,42 ,  34 ,  26  ,18  , 10  , 2,
            60  ,  52 ,44 ,  36 ,  28  ,20  , 12  , 4,
            62  , 54  ,46 ,  38 ,  30  ,22  , 14  , 6,
            64  , 56  ,48 ,  40 ,  32  ,24  , 16  , 8,
            57  , 49  ,41 ,  33 ,  25  ,17  ,  9  , 1,
            59  , 51  ,43 ,  35 ,  27  ,19  , 11  , 3,
            61  , 53  ,45 ,  37 ,  29  ,21  , 13  , 5,
            63  , 55  ,47 ,  39 ,  31  ,23  , 15  , 7
            };
            return IP;
        }
        public string ValidateInputIP(string text)
        {
            int[] IP = GenerateIP();
            string result = "";
            for (int i = 0; i < text.Length; i++)
                result += text[(IP[i] - 1)];
            return result;

        }
        public string ValidateKeyPC1(string text)
        {
            int[] PC = GeneratePC1();
            string result = "";
            for (int i = 0; i < PC.Length; i++)
                result += text[(PC[i] - 1)];
            return result;

        }
        public int[] Iteration()
        {
            int[] iteration = {
                                   1,
                                   1,
                                   2,
                                   2,
                                   2,
                                   2,
                                   2,
                                   2,
                                   1,
                                   2,
                                   2,
                                   2,
                                   2,
                                   2,
                                   2,
                                   1
            };
            return iteration;
        }
        public void KeySchedular(ref string C, ref string D, string b2 , string b1)
        {
            int[] Itr = Iteration();
            //1-Left Circular Shift
            string TempC = "";
            string TempD = "";
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < Itr[i]; j++)
                {

                    for (int k = 1; k <= 27; k++)
                    {
                        TempC += C[k];
                        TempD += D[k];
                    }

                    TempC = TempC + C[0];
                    TempD = TempD + D[0];
                    C = TempC;
                    D = TempD;
                    TempC = "";
                    TempD = "";
                }
                string CnDn = C + D;
                int[] PC2 = GeneratePC2();
                string Ks = "";
                for (int j = 0; j < PC2.Length; j++)
                {
                    Ks += CnDn[(PC2[j] - 1)];
                }

               string newB2 = ValidateSelectionTable(b2);
                string XORresult = "";
                for (int j = 0; j < newB2.Length; j++)
                {
                    XORresult += newB2[j] ^ Ks[j];
                }
                string Bs;
                int step = 0;
                string str = "";
                string parts = "";
                for (int m =0; m<8;m++)

                {
                    str = "";
                   
                        Bs= XORresult.Substring(step,6);
                        step += 6;
                    str += Bs[0];
                    str+= Bs[5];
                   int  row = Convert.ToInt32(str, 2);
                    str = "";
                    str += Bs[1];
                    str += Bs[2];
                    str += Bs[3];
                    str += Bs[4];
                    int col = Convert.ToInt32(str, 2);
                    int[,] sbox = Sbox(m+1);
                    parts += Convert.ToString(sbox[row, col], 2).PadLeft(4,'0');
                 
                }

                int[] perm = permutation();
                string result = "";
                for (int m = 0; m < perm.Length; m++)
                    result += parts[(perm[m] - 1)];
                string trans = "";
                    string trans1 = "";
                    string trans2 = "";
                    string trans3 = "";
                    string trans4 = "";
                for ( int m =result.Length-1; m>=0;m--)
                {
                    if (m % 4 == 0)
                        trans1 += result[m];
                    else if (m % 4 == 1)
                        trans2 += result[m];
                    else if (m % 4 == 2)
                        trans3 += result[m];
                    else if (m % 4 == 3)
                        trans4 += result[m];

                    if (m == 0)
                    {
                        trans += trans1;
                        trans += trans2;
                        trans += trans3;
                        trans += trans4;

                    }
                }
                string result2 = "";
                for (int m = 0; m < b1.Length; m++)
                    result2 += b1[m] ^ trans[m];


            }



        }
        public int[] GeneratePC2()
        {
            int[] PC_2 ={
                 14 ,   17 ,  11 ,   24 ,    1 ,   5,
                  3 ,   28 ,  15 ,    6 ,   21 ,  10,
                 23 ,   19 ,  12 ,    4 ,   26 ,   8,
                 16 ,    7 ,  27 ,   20 ,   13 ,   2,
                 41 ,   52 ,  31 ,   37 ,   47 ,  55,
                 30 ,   40 ,  51 ,   45 ,   33 ,  48,
                 44 ,   49 ,  39 ,   56 ,   34 ,  53,
                 46 ,   42 ,  50 ,   36 ,   29 ,  32 };
            return PC_2;
        }
        public int[] BitSelection()
        {
            int[] BS = {

                 32 ,    1  ,  2 ,    3   ,  4 ,   5,
                  4  ,   5 ,   6  ,   7   ,  8  ,  9,
                  8   ,  9 ,  10  ,  11  ,  12  , 13,
                 12  ,  13 ,  14  ,  15   , 16  , 17,
                 16  ,  17 ,  18  ,  19  ,  20 ,  21,
                 20  ,  21 ,  22  ,  23  ,  24  , 25,
                 24  ,  25  , 26  ,  27  ,  28  , 29,
                 28  ,  29 ,  30  ,  31 ,   32  ,  1
};
            return BS;
        }
        public string ValidateSelectionTable(string b2)
        {
            int[] BS = BitSelection();
            string result = "";
            for (int i = 0; i < BS.Length; i++)
                result += b2[(BS[i] - 1)];
            return result;
             
        }
        public int[,] Sbox(int x)
        {
            int[,] sbox ;
            if (x == 1)
            {
                sbox = new int[4, 16] {
                        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
                return sbox;
            }
            else if (x == 2)
            {

                sbox = new int[4, 16] {

            { 15,  1,   8, 14,   6, 11  , 3,  4,   9,  7,   2, 13,  12,  0,   5, 10},
            { 3, 13,   4,  7,  15,  2  , 8, 14,  12,  0,   1, 10,   6,  9,  11,  5},
            { 0, 14,   7, 11,  10,  4  ,13,  1,   5,  8,  12,  6,   9,  3,   2, 15},
            { 13,  8,  10,  1,   3, 15  , 4,  2,  11,  6,   7, 12,   0,  5,  14,  9}};
                return sbox;
            }
            else if (x == 3)
            {
                sbox = new int[4, 16] {
           { 10,  0,   9, 14,   6,  3  ,15,  5,   1, 13,  12,  7,  11,  4,   2,  8 },
            {13,  7,   0,  9,   3,  4  , 6, 10,   2,  8,   5, 14,  12, 11,  15,  1 },
            {13,  6,   4,  9,   8, 15  , 3,  0,  11,  1,   2, 12,   5, 10,  14,  7 },
            { 1, 10,  13,  0,   6,  9  , 8,  7,   4, 15,  14,  3,  11,  5,   2, 12}
             };
                return sbox;
            }

            else if (x == 4)
            {
                sbox = new int[4, 16] {
                     { 7, 13,  14,  3,   0,  6  , 9, 10,   1,  2,   8,  5,  11, 12,   4, 15 },
                    {13,  8,  11,  5,   6, 15  , 0,  3,   4,  7,   2, 12,   1, 10,  14,  9},
                    {10,  6,   9,  0,  12, 11  , 7, 13,  15,  1,   3, 14,   5,  2,   8,  4},
                    { 3, 15,   0,  6,  10,  1  ,13,  8,   9,  4,   5, 11,  12,  7,   2, 14}

                }; return sbox;
            }

            else if (x == 5)
            {
                sbox = new int[4, 16] {
                { 2, 12,   4,  1,   7, 10  ,11,  6,   8,  5,   3, 15,  13,  0,  14,  9 },
                {14, 11,   2, 12,   4,  7  ,13,  1,   5,  0,  15, 10,   3,  9,   8,  6},
                { 4,  2,   1, 11,  10, 13  , 7,  8,  15,  9,  12,  5,   6,  3,   0, 14},
                {11,  8,  12,  7,   1, 14  , 2, 13,   6, 15,   0,  9,  10,  4,   5,  3} };
                return sbox;
            }


            else if (x == 6)
            {
                sbox = new int[4, 16] {
                {12,  1,  10, 15,   9,  2  , 6,  8,   0, 13,   3,  4,  14,  7,   5, 11 },
                {10, 15,   4,  2,   7, 12  , 9,  5,   6,  1,  13, 14,   0, 11,   3,  8},
                { 9, 14,  15,  5,   2,  8  ,12,  3,   7,  0,   4, 10,   1, 13,  11,  6},
                { 4,  3,   2, 12,   9,  5  ,15, 10,  11, 14,   1,  7,   6,  0,   8, 13} };
                return sbox;
            }


            else if (x == 7)
            {
                sbox = new int[4, 16] {
                { 4, 11,   2, 14,  15,  0  , 8, 13,   3, 12,   9,  7,   5, 10,   6,  1 },
                {13,  0,  11,  7,   4,  9  , 1, 10,  14,  3,   5, 12,   2, 15,   8,  6},
                { 1,  4,  11, 13,  12,  3  , 7, 14,  10, 15,   6,  8,   0,  5,   9,  2},
                { 6, 11,  13,  8,   1,  4  ,10,  7,   9,  5,   0, 15,  14,  2,   3, 12} };
                return sbox;
            }
            else if (x == 8)
            {
                sbox = new int[4, 16] {
                {13,  2,   8,  4,   6, 15  ,11,  1,  10,  9,   3, 14,   5,  0,  12,  7},
                { 1, 15,  13,  8,  10,  3  , 7,  4,  12,  5,   6, 11,   0, 14,   9,  2},
                { 7, 11,   4,  1,   9, 12  ,14,  2,   0,  6,  10, 13,  15,  3,   5,  8},
                { 2,  1,  14,  7,   4, 10  , 8, 13,  15, 12,   9,  0,   3,  5,   6, 11 } };
                return sbox;
            }


                return null ;
        }
        public int[] permutation()
        {
            int[] per = {
                         16 ,  7,  20,  21,
                         29 , 12,  28,  17,
                          1 , 15,  23,  26,
                          5 , 18,  31,  10,
                          2 ,  8,  24,  14,
                         32 , 27,   3,   9,
                         19 , 13,  30,   6,
                         22 , 11,   4,  25

            };

            return per;
        }

    }



}

