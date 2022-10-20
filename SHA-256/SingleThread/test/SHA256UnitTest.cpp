#include "SHA256UnitTest.h"
#include "SHA256.h"

TEST(SHA256Test, SmallString)
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
    string ans = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}

TEST(SHA256Test, LongString)
{
    SHA256 sha256;
    string str = "abcdef2345562--56fcq;q;eeelelelabcdef2345562--56fcq;q;eeelelelabcdef2345562--56fcq;q;eeelelel";
    string hash = sha256.calculateSHA256(str);
    string ans = "cf3bae546f420b5a0ed9a95c09a290f0852c1b013885f896f4719f7af42d0bee";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}

TEST(SHA256Test, Passage)
{
    SHA256 sha256;
    string str = "Polling expert Professor Sir John Curtice says we should remember that Boris Johnson "
     "still faces a parliamentary investigation by the privileges committee into whether he deliberately "
      "misled the Commons over Downing Street parties.";
    string hash = sha256.calculateSHA256(str);
    string ans = "4ef17f2635f1daff784f1843c61b27c7f87519c97321642f932eea14d3683e5e";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}

TEST(SHA256Test, Numbers)
{
    SHA256 sha256;
    string str = "3.141592653589793238462643383279502884197169399375105820974944592307816406286" 
                  "208998628034825342117067982148086513282306647093844609550582231725359408128481"
                  "117450284102701938521105559644622948954930381964428810975665933446128475648233" 
                  "786783165271201909145648566923460348610454326648213393607260249141273724587006"
                  "606315588174881520920962829254091715364367892590360011330530548820466521384146" 
                  "951941511609433057270365759591953092186117381932611793105118548074462379962749";
    string hash = sha256.calculateSHA256(str);
    string ans = "1118b5cf36ede10a5968d249b478915d2c9f2ba4097f3b4436a5b68eb31425e5";
    EXPECT_STRCASEEQ(ans.c_str(), hash.c_str());
}
