using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int nxn = 2;
            int[,] PT = new int[nxn, (plainText.Count / 2)];
            int[,] CT = new int[nxn, (cipherText.Count / 2)];
            int[,] newPT = new int[nxn, nxn];
            float[,] newPTx = new float[nxn, nxn];
            int[,] newCT = new int[nxn, nxn];
            int[,] key = new int[2, 2];
            int start = 0;
            List<int> keyListout = new List<int>(4);
            List<int> CipherCHeck = new List<int>();
            List<int> PTList = new List<int>(4);
            List<int> CTList = new List<int>(4);

         
            for (int i = 0; i < plainText.Count/2; i++)
            {
           
                for (int j = 0; j < nxn ; j++)
                {
                    PT[j, i] = plainText[start];
                    CT[j, i] = cipherText[start++];
                }
            }

            for (int i = 0; i < (plainText.Count / 2) - 1; i++)
            {
                newPT[0, 0] = PT[0, i];
                newPT[1, 0] = PT[1, i];
                newCT[0, 0] = CT[0, i];
                newCT[1, 0] = CT[1, i];
                for (int j = i + 1; j < (plainText.Count / 2); j++)
                {
                    newPT[0, 1] = PT[0, j];
                    newPT[1, 1] = PT[1, j];


                    newCT[0, 1] = CT[0, j];
                    newCT[1, 1] = CT[1, j];

                    double dyz = DETE(nxn, newPT);
                    dyz %= 26;
                    if (dyz < 0)
                        dyz += 26;


                    int b = 0;
                    //d = 26 - (int)dyz;

                    b = modInverse((int)dyz);
                    if (b == -101)
                        continue;
                    if (b < 0)
                        b += 26;
                    int inv = 0;
                    float A, B, C, D;
                    A = (newPT[0, 0]);
                    B = (newPT[0, 1]);
                    C = (newPT[1, 0]);
                    D = (newPT[1, 1]);
                    // inv =  ((A * D) - (B * C));
                    //   inv = (int)dyz;
                    inv = (int)b;
                    A *= inv;
                    B *= inv * -1;
                    C *= inv * -1;
                    D *= inv;
                    A %= 26;
                    B %= 26;
                    C %= 26;
                    D %= 26;
                    if (A < 0)
                        A += 26;
                    if (B < 0)
                        B += 26;
                    if (C < 0)
                        C += 26;
                    if (D < 0)
                        D += 26;

                    (newPTx[0, 0]) = D;
                    (newPTx[0, 1]) = B;
                    (newPTx[1, 0]) = C;
                    (newPTx[1, 1]) = A;


                    keyListout = multMat(2, newPTx, newCT);
                    CipherCHeck = Encrypt(plainText, keyListout);
                    int cnt = 0;
                    for (int s = 0; s < plainText.Count; s++)
                    {
                        if (CipherCHeck[s] == cipherText[s])
                            cnt++;
                    }
                    if (cnt == plainText.Count)
                        return keyListout;
                }
            }
                                          
            throw new InvalidAnlysisException();
        }
         int modInverse(int b)
        {
         
            int A1 = 1;
            int A2 = 0;
            int A3 = 26;
            int B1 = 0;
            int B2 = 1;
            int B3 = b;
            double T1, T2, T3;
            double Q;
            while (true)
            {
                if (B3 == 0)
                    return -101;
                else if (B3 == 1)
                    return B2;
                Q = A3 / B3;
                T1 = A1 - Q * B1;
                T2 = A2 - Q * B2;
                T3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = (int)T1;
                B2 = (int)T2;
                B3 = (int)T3;
            }

        }

        List<int> multMat(int mxm,float[,]plainTextMatrixOutput , int[,] cipherTextMatrix)
        {

            double[,] key = new double[mxm, mxm];
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    key[i, j] = 0;
                    for (int k = 0; k < mxm; k++)
                    {
                        key[i, j] += cipherTextMatrix[i, k]*plainTextMatrixOutput[k, j];

                    }
                    key[i, j] %= 26;
                  
                }
            }

            List<int> keys = new List<int>();

            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    keys.Add((int)key[i,j]);

                }
               
            }
            return keys;
        }
      

        public List<int> Decrypt(List<int> cipherText, List<int> key)

        {

            List<int> keyT = new List<int>(key.Count);
            int mxm = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = new int[mxm, mxm];
            //ba7utaha henna f 2D matrix cip[]
            int counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((key[counter] >= 0) && (key[counter] <= 26))
                        keyMatrix[i, j] = key[counter++];
                    else if (key[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = key[counter];
                        x %= 26;
                        keyMatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative 

                        break;

                    }
                }
            }  //da output el determinant
            double dyz = DETE(mxm, keyMatrix);
            dyz %= 26;
            if (dyz < 0)
                dyz += 26;

            int gcd = GCD((int)dyz);

            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (gcd != 1)
                throw new InvalidAnlysisException();

            if (mxm == 2)
            {

                float inv = 0;
                float A, B, C, D;
                A = (keyMatrix[0, 0]);
                B = (keyMatrix[0, 1]);
                C = (keyMatrix[1, 0]);
                D = (keyMatrix[1, 1]);
                inv = 1 / ((A * D) - (B * C));
                A *= inv;
                B *= inv * -1;
                C *= inv * -1;
                D *= inv;
                //B *= -1;
                //C *= -1;
                key[0] = (int)D;
                key[1] = (int)B;
                key[2] = (int)C;
                key[3] = (int)A;

                return Encrypt(cipherText, key);

            }
            //d henna heya el 3 
            double c = 0, b = 0, d = 0;
            d = 26 - dyz;

            counter = 1;
            for (int i = 0; i < 1000; i++)
            {

                if ((26 * counter + 1) % d != 0)
                    counter++;
                else
                    break;
            }
            c = (26 * counter + 1) / d;


            b = 26 - c;

            int[,] SUBMat = new int[mxm - 1, mxm - 1];
            double[,] keyMatrixOutput = new double[mxm, mxm];
            int jCounter = 0;
            int iCounter = 0;
            //ensa kol elly fu2 dah kolo sa7 
            //h3tber el loop el k de btlef 3l myten om el row

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    // for every cell in key matrix(3*3)
                    int I = 0, J = 0;
                    for (int x = 0; x < 3; x++)
                        for (int y = 0; y < 3; y++)
                        {
                            // for every cell in key matrix 3*3 that
                            // doesn't share a column or row with cell[i,j]

                            if (!(x == i || y == j))
                            {
                                SUBMat[I, J] = keyMatrix[x, y];
                                // increment the column counter once
                                J++;
                                // if J == 2 add 1 to the row counter
                                I += (J / 2);
                                // set J to J%2 (always cuz i'm a lazy man)
                                J %= 2;
                                // naw I point to the row index and J point to the column index
                                // have fun <3
                            }


                        }
                    double ans = DETE(mxm - 1, SUBMat);

                    double answer = (b * (Math.Pow(-1, (i + j)) * ans) % 26);
                    if (answer < 0)
                        answer += 26;
                    keyMatrixOutput[iCounter, jCounter] = answer;
                    jCounter++;
                    if (jCounter > 2)
                    {
                        jCounter = 0;
                        iCounter++;
                    }

                }
            }


            int w = keyMatrixOutput.GetLength(0);
            int h = keyMatrixOutput.GetLength(1);

            double[,] result = new double[h, w];

            for (int i = 0; i < w; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    result[j,i] = keyMatrixOutput[i, j];
                }
            }
            // keyMatrixOutput = Transpose(keyMatrixOutput);
            keyMatrixOutput = result;
            counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    key[counter] = (int)keyMatrixOutput[i, j];
                    counter++;
                }
            }
            return Encrypt(cipherText, key);


        }
     
        //betgeb el determinant beta3 el matrix
        public double DETE(int mxm, int[,] keyMatrix)
        {
          
            int[,] SUBMat = new int[mxm - 1, mxm - 1];
            double dy = 0;
            if (mxm == 2)
            {
                return ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));
            }

            else if (mxm == 3)
            {

                for (int k = 0; k < mxm; k++)
                {
                    int subi = 0;
                    for (int i = 1; i < mxm; i++)
                    {
                        int subj = 0;
                        for (int j = 0; j < mxm; j++)
                        {
                            if (j == k)
                            {
                                continue;
                            }
                            SUBMat[subi, subj] = keyMatrix[i, j];
                            subj++;
                        }
                        subi++;
                    }
                    double ans = DETE(mxm - 1, SUBMat);
                    dy = dy + (Math.Pow(-1, k) * keyMatrix[0, k] *ans );
                }

            }
            return dy;
        }

        public double[,] Transpose(double[,] matrix)
        {
            int w = matrix.GetLength(0);
            int h = matrix.GetLength(1);

            double[,] result = new double[h, w];

            for (int i = 0; i < w; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    result[i, j] = matrix[i, j];
                }
            }

            return result;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher = new List<int>(plainText.Count);
            for (int i = 0; i < plainText.Count; i++)
            {
                cipher.Add(0);
            }
            //3shan ye3rf el key matrix kam f kam el mafroud
            int m = (int)Math.Sqrt(key.Count);
            int inx2 = 0;
            for (int i = 0; i < plainText.Count; i += m)
            {
                int acc = 0, val = 0;
                for (int j = 0; j <= key.Count; j++)
                {
                    if (acc == m)
                    {
                        val %= 26;
                        if (val < 0)
                            val += 26;
                        cipher[inx2] = val;
                        acc = 0;
                        val = 0;
                        inx2++;
                        if (j == key.Count)
                            break;

                    }
                    val += (plainText[i + acc] * key[j]);
                    acc++;

                }
            }
            return cipher;

        }

        private static int GCD(int a)
        {
            int b = 26;
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a == 0 ? b : a;

           }

        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int mxm = (int)Math.Sqrt(plainText.Count);
            double[,] cipherTextMatrix = new double[mxm, mxm];
            //ba7utaha henna f 2D matrix cip[]
            int counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((cipherText[counter] >= 0) && (cipherText[counter] <= 26))
                        cipherTextMatrix[j, i] = cipherText[counter++];
                    else if (cipherText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = cipherText[counter];
                        x %= 26;
                        cipherTextMatrix[ j,i] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative 

                        break;

                    }
                }
            }

            int[,] plainTextMatrix = new int[mxm, mxm];
            //ba7utaha henna f 2D matrix cip[]
            counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((plainText[counter] >= 0) && (plainText[counter] <= 26))
                        plainTextMatrix[i, j] = plainText[counter++];
                    else if (plainText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = plainText[counter];
                        x %= 26;
                        plainTextMatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative
                        break;

                    }
                }
            }
            double dyz = DETE(mxm, plainTextMatrix);
            dyz %= 26;
            if (dyz < 0)
                dyz += 26;
            int gcd = GCD((int)dyz);

            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (gcd != 1)
                throw new InvalidAnlysisException();
            //d henna heya el 3 
            double c = 0, b = 0, d = 0;
            d = 26 - dyz;
            // c = 27 / d;
            counter = 1;

            for (int i = 0; i < 1000; i++)
            {

                if ((26 * counter + 1) % d != 0)
                    counter++;
                else
                    break;
            }
            c = (26 * counter + 1) / d;


            b = 26 - c;
            int[,] SUBMat = new int[mxm - 1, mxm - 1];
            double[,] plainTextMatrixOutput = new double[mxm, mxm];
            int jCounter = 0;
            int iCounter = 0;
           
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    // for every cell in key matrix(3*3)
                    int I = 0, J = 0;
                    for (int x = 0; x < 3; x++)
                        for (int y = 0; y < 3; y++)
                        {
                            // for every cell in key matrix 3*3 that
                            // doesn't share a column or row with cell[i,j]

                            if (!(x == i || y == j))
                            {
                                SUBMat[I, J] = plainTextMatrix[x, y];
                                // increment the column counter once
                                J++;
                                // if J == 2 add 1 to the row counter
                                I += (J / 2);
                                // set J to J%2 (always cuz i'm a lazy man)
                                J %= 2;
                                // naw I point to the row index and J point to the column index
                                // have fun <3
                            }


                        }
                    double ans = DETE(mxm - 1, SUBMat);

                    double answer = (b * (Math.Pow(-1, (i + j)) * ans) % 26);
                    if (answer < 0)
                        answer += 26;
                    plainTextMatrixOutput[iCounter, jCounter] = answer;
                    jCounter++;
                    if (jCounter > 2)
                    {
                        jCounter = 0;
                        iCounter++;
                    }

                }
            }


            plainTextMatrixOutput = Transpose(plainTextMatrixOutput);
            int cimxm = (int)Math.Sqrt(cipherText.Count);
            double[,] key = new double[mxm, cimxm];
            for (int i = 0; i < 3; i++)//K
            {
                for (int j = 0; j < mxm; j++)//I
                {
                    key[i, j] = 0;
                    for (int k = 0; k < mxm; k++)//J
                    {
                        //{ 1, 10, 0, 0, 20, 1, 2, 15, 2 }
                        // key[i, j] += plainTextMatrixOutput[i, k] * cipherTextMatrix[k, j];
                        //  key[j, i] +=  cipherTextMatrix[k, j]*plainTextMatrixOutput[i, k] ;
                        // key[j, i] += cipherTextMatrix[i,k] * plainTextMatrixOutput[k, j];
                        //  key[ i,j] += cipherTextMatrix[i, k] * plainTextMatrixOutput[k, 1];
                      
                        key[i, j] += (cipherTextMatrix[j, k] * plainTextMatrixOutput[k, i]);
                        key[i, j] %= 26;
                    }
                    //  key[i, j]%=26;
                }
            }
         
            List<int> keys = new List<int>(9);
            
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    keys.Add((int)key[ j,i]);

                }
            }
            return keys;


        }
        
    }
}
