// g++ -g -O2 -std=c++11 -pthread -march=native ECDSA.cpp -o ECDSA -lntl -lgmp -lm -lssl -lcrypto

#include <iostream>
#include <NTL/ZZ.h>
#include <openssl/sha.h>
#include <cstring>

#define MESSAGE_SPACE 256

using namespace std;
using namespace NTL;

char buf_P[] = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
char buf_n[] = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
char buf_A[] = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
char buf_B[] = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
char buf_Gx[] = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
char buf_Gy[] = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

ZZ P;    // modulus
ZZ A, B; // coefficient

ZZ hextodecimal(const unsigned char *str, const int length);

class PointFp
{
private:
    ZZ x, y; //좌표
    bool is_zero = false;

public:
    PointFp()
    {
        this->x = 0;
        this->y = 0;
    }
    PointFp(bool _is_zero)
    {
        this->is_zero = _is_zero;
    }

    PointFp(ZZ _x, ZZ _y)
    {
        this->x = _x % P;
        this->y = _y % P;
    }

    PointFp operator+(const PointFp &point)
    {
        PointFp result;
        ZZ grad; //기울기

        if (this->is_zero || point.is_zero) // 두 점 중 하나라도 영점이라면
        {
            if (this->is_zero && point.is_zero) // 두 점 모두 영점인 경우
                result.is_zero = true;
            else if (this->is_zero)
                result = point;
            else
                result = *this;

            return result;
        }
        else
        {
            if (this->x == point.x && this->y == point.y) // 같은 점에 대한 연산이라면
            {
                ZZ num1 = AddMod(MulMod(3, SqrMod(this->x, P), P), A, P);
                ZZ num2 = MulMod(2, this->y, P); //분모

                grad = MulMod(num1, InvMod(num2, P), P);
            }

            else if (this->x == point.x && this->y != point.y) // 연산의 결과가 무한영점(항등원) 인 경우
            {
                result.is_zero = true;
                return result;
            }

            else // 서로 다른 점에 대한 연산이라면
            {
                ZZ delta_x = SubMod(point.x, this->x, P);
                ZZ delta_y = SubMod(point.y, this->y, P);

                grad = MulMod(delta_y, InvMod(delta_x, P), P);
            }
            result.set_x((SqrMod(grad, P) - this->x - point.x) % P);
            result.set_y(SubMod(MulMod(grad, SubMod(this->x, result.x, P), P), this->y, P));
            return result;
        }
    }

    void set_x(ZZ _x)
    {
        this->x = _x;
    }
    void set_y(ZZ _y)
    {
        this->y = _y;
    }
    ZZ get_x()
    {
        return this->x;
    }
    ZZ get_y()
    {
        return this->y;
    }
    bool get_iszero()
    {
        return this->is_zero;
    }

    friend PointFp operator*(ZZ n, const PointFp &point);
};

class ECDSA
{
private:
    /// public key ///
    ZZ h = ZZ(1); // cofactor
    ZZ n;
    ZZ Q;
    ZZ Gx, Gy; // 제너레이터 좌표
    PointFp p_gen, p_pub;

    /// private key ///
    ZZ d;

public:
    ECDSA() // key generation
    {

        P = hextodecimal((const unsigned char *)buf_P, strlen(buf_P));
        n = hextodecimal((const unsigned char *)buf_n, strlen(buf_n));
        Q = n * h;
        A = hextodecimal((const unsigned char *)buf_A, strlen(buf_A));
        B = hextodecimal((const unsigned char *)buf_B, strlen(buf_B));
        Gx = hextodecimal((const unsigned char *)buf_Gx, strlen(buf_Gx));
        Gy = hextodecimal((const unsigned char *)buf_Gy, strlen(buf_Gy));

        do
        {
            d = RandomBnd(Q);
        } while (d == ZZ(0));

        p_gen.set_x(Gx);
        p_gen.set_y(Gy);

        p_pub = d * p_gen;
    }

    void Signature(const ZZ m, ZZ &r, ZZ &s)
    {
        ZZ k;
        do
        {
            k = RandomBnd(Q);
        } while (k == ZZ(0));

        PointFp p_r = k * p_gen;

        r = p_r.get_x() % Q;
        s = MulMod(InvMod(k, Q), AddMod(m, MulMod(r, d, Q), Q), Q);
    }

    bool Verification(const ZZ m, const ZZ r, const ZZ s)
    {
        ZZ w = InvMod(s, Q);
        ZZ u1 = MulMod(w, m, Q);
        ZZ u2 = MulMod(w, r, Q);
        PointFp p_v = u1 * p_gen + u2 * p_pub;

        cout << "r : " << r << endl;
        cout << "v : " << p_v.get_x() << endl;

        if (p_v.get_x() % Q == r)
            return true;
        else
            return false;
    }
};

int main(int argc, char **argv)
{
    unsigned char msg[MESSAGE_SPACE] = "my name is hoo";
    unsigned char *digest = new unsigned char[SHA256_DIGEST_LENGTH];

    memset(digest, 0x00, SHA256_DIGEST_LENGTH);
    SHA256(msg, strlen((char *)msg), digest);

    ZZ r, s;
    ZZ m = ZZFromBytes(digest, SHA256_DIGEST_LENGTH);
    
    ECDSA e;
    cout << "msg : " << msg << endl;
    cout << "m : " << m << endl;

    e.Signature(m, r, s);

    if (e.Verification(m, r, s))
        cout << "valid siginture" << endl;

    else if (!e.Verification(m, r, s))
        cout << "invalid signiture" << endl;

    return 0;
}

ZZ hextodecimal(const unsigned char *str, const int length) //16진수 -> 10진수 변환 
{
    ZZ num = ZZ(0);
    ZZ count = ZZ(1);

    for (int i = 1; i <= length; i++)
    {
        if ('A' <= str[length - i] && str[length - i] <= 'F')
            num += count * (str[length - i] - 'A' + 10);
        
        else if ('0' <= str[length - i] && str[length - i] <= '9')
            num += count * (str[length - i] - '0');

        else if ('a' <= str[length - i] && str[length - i] <= 'f')
            num += count * (str[length - i] - 'a' + 10);

        else
        {
            cout << "convert error" << endl;
            break;
        }
        count = count * 16;
    }
    return num;
}

PointFp operator*(ZZ n, const PointFp &point)
{
    PointFp result = PointFp(true);
    PointFp temp = point;

    while (n > 0)
    {
        if (n % 2 == 1)
            result = result + temp;

        n = n / 2;
        temp = temp + temp;
    }
    return result;
}
