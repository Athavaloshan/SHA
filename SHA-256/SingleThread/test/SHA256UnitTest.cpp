#include "SHA256UnitTest.h"
#include "SHA256.h"

TEST(SHA256Test, String)
{
    SHA256 sha256;
    string str = "abc";
    string hash = sha256.calculateSHA256(str);
    string ans = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}

TEST(SHA256Test, Empty)
{
    SHA256 sha256;
    string str = "";
    string hash = sha256.calculateSHA256(str);
    string ans = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}
