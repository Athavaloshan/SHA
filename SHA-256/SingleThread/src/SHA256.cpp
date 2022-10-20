#include "SHA256.h"

SHA256::SHA256()
{
    h0 = 0x6a09e667;
    h1 = 0xbb67ae85;
    h2 = 0x3c6ef372;
    h3 = 0xa54ff53a;
    h4 = 0x510e527f;
    h5 = 0x9b05688c;
    h6 = 0x1f83d9ab;
    h7 = 0x5be0cd19;
    
}

uint32_t SHA256::rotateLeft(uint32_t data, int d)
{
    return rotateLeft(data, (32 - d));//data is lenght of 32 bit 
}

void addNumberAndString(string str, uint8_t number)
{
    str += to_string(number);
}

uint32_t SHA256::rotateRight(uint32_t data, int d)
{
    for (int i = 0; i < d; ++i)
    {
        uint32_t tmp = data & 0x1;
        data >>= 1; 
        data = (data | (tmp << 31));  
    }    

    return data;
}

void SHA256::preProcess(string & data)
{
    uint64_t originalLength = data.length() * 8;//length in bits
    int lastBlockLength = data.length()%512;
    long L = lastBlockLength * 8;// number of bits (1 char = 8 bits) // TODO verify
    int numberOfZeros = 512 - (64 + (L%512 ) + 1);

    data += char(0x80); //0'b1000 0000

    if (numberOfZeros - 7 > 0)
    {
        int iteration = (numberOfZeros - 7 ) / 8;
        
        for (int i = 0; i < iteration; ++i)
        {
            data += char(0x00);
        } 
    }

    string lengthOfData = "";

    for (int i = 0; i < 8; ++i)
    {
        lengthOfData += char(originalLength & 0xff);
        originalLength >>= 8; 
    }

    reverse(lengthOfData.begin(), lengthOfData.end());

    data += lengthOfData;
}

void SHA256::convertBlockToCharArray(string &  str, uint8_t * charArray)
{
    for (int i = 0; i < 64; ++i) // 512/8 = 64
    {
        charArray[i] = str[i];
    }
}

string  SHA256::convertToString(uint32_t number)
{
    string str = "";

    for (int i = 0; i < 8; ++i)
    {
        int8_t tmp = (number & 0xf);
        if (tmp < 10)
        {
            str = to_string(tmp) + str;
        }
        else
        {
            str = char(55 + tmp) + str;
        }
        number >>= 4;
    }

    return str;
}

string SHA256::convertStringToHex(string & data)
{
    string result = "0x";

    for (int i = 0; i < data.length(); ++i)
    {
        uint8_t number = int(data[i]);
        for (int j = 0; j < 2; ++j)
        {

            uint8_t tmp = (number & 0xf0);
            tmp = (tmp >> 4) & 0xf;
            if (tmp < 10)
            {
                result += to_string(tmp);
            }
            else
            {
                result += char(55 + tmp);
            }
            number <<= 4;
        }
    }

    return result;
}

void SHA256::process(uint8_t * charArray) // chararray is of length 64
{
    uint32_t w[64];

    for (int i = 0; i < 16; ++i)
    {
        int currentCharArrayIndex = i * 4;
        w[i] = (charArray[currentCharArrayIndex] << 24) + (charArray[currentCharArrayIndex + 1] << 16) + 
               (charArray[currentCharArrayIndex + 2] << 8) + charArray[currentCharArrayIndex + 3];
        // cout << "W[" << i << "]" << w[i] << endl;
    }

    for (int i = 16; i < 64; ++i)
    {
        uint32_t s0   = ((rotateRight(w[i-15], 7)) ^ (rotateRight(w[i-15], 18)) ^ (w[i-15] >> 3));
        uint32_t s1   = ((rotateRight(w[i-2], 17)) ^ (rotateRight(w[i-2], 19)) ^ (w[i-2] >> 10));
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    //Compression function main loop:
    for (int i = 0; i < 64; ++i)
    {
        uint32_t S1 = (rotateRight(e, 6)) ^ (rotateRight(e, 11)) ^ (rotateRight(e,25));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = (rotateRight(a, 2)) ^ (rotateRight(a, 13)) ^ (rotateRight(a ,22));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
 
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the compressed chunk to the current hash value:
    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;
    h5 = h5 + f;
    h6 = h6 + g;
    h7 = h7 + h;

    // cout << hex << "h0 : " << h0 << endl;
    // cout << "h1 : " << h1 << endl;
    // cout << "h2 : " << h2 << endl;
    // cout << "h3 : " << h3 << endl;
    // cout << "h4 : " << h4 << dec <<endl;

}

string SHA256::calculateSHA256(string str)
{
    // cout << "Input data " << convertStringToHex(str) << " length : " << str.length() << endl;
    preProcess(str);
    // cout << "After pre processing data " << convertStringToHex(str) << " length : " << str.length() << endl;
    long currPos = 0;
    string currString;
    long numberOfBlocks = (str.length() * 8)/512; //multiply by 8 to convert the lenght to nymber of bits

    for(int i = 0; i < numberOfBlocks; ++i)
    {
        uint8_t charArray[64];//can optimize by creating once & reuse it 

        currString = str.substr(currPos, 64);// 64 char = 512 bit
        // cout << "Current block : " << currString << " length : " << currString.length() << endl; 
        convertBlockToCharArray(currString, charArray);
        process(charArray);
        currPos += 64;
    }

    // Produce the final hash value (big-endian):
    string digest = convertToString(h0) + convertToString(h1)  + convertToString(h2) 
    + convertToString(h3) + convertToString(h4) + convertToString(h5) 
    + convertToString(h6) + convertToString(h7);

    return digest;
}



