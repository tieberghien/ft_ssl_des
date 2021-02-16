#include "ft_ssl_md5.h"
/*
static const int g_sbox1[64] =
{
	14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
	 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
	 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
	15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13
};

static const int g_sbox2[64] =
{
	15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
	 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
	 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
	13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9
};

static const int g_sbox3[64] =
{
	10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
	13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
	13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
	 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12
};

static const int g_sbox4[64] =
{
	 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
	13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
	10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
	 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14
};

static const int g_sbox5[64] =
{
	 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
	14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
	 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
	11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3
};

static const int g_sbox6[64] =
{
	12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11,
	10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
	 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
	 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13
};

static const int g_sbox7[64] =
{
	 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
	13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
	 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
	 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12
};

static const int g_sbox8[64] =
{
	13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
	 1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
	 7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
	 2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11
};
*/

void des_encrypt_block(t_pkbdf *df)
 {
    uint_t i;
    uint32_t left;
    uint32_t right;
    uint32_t temp;
  
    //Key schedule
    uint32_t *ks = df->key;
  
    //Copy the plaintext from the input buffer
    lefit = LOAD32BE(df->input + 0);
    right = LOAD32BE(df->input + 4);
  
    //Initial permutation
    DES_IP(left, right);
  
    //16 rounds of computation are needed
    for(i = 0; i < 16; i++, df->key += 2)
    {
       DES_ROUND(left, right, ks);
    }
  
    //Inverse IP permutation
    DES_FP(right, left);
  
    //Copy the resulting ciphertext
    STORE32BE(right, output + 0);
    STORE32BE(left, output + 4);
}

void	padding_message(uint32_t c, uint8_t data[])
{
	int	i;
	int	j;

	i = -1;
	j = 0;
	while (++i < 16)
	{
		c = (data[j]) + (data[j + 1] << 8) + (data[j + 2] << 16)
			+ (data[j + 3] << 24);
		j += 4;
	}
}


int des_init(t_pbkdf *df, uint8_t key[], size_t keylen)
 {
    uint_t i;
    uint32_t c;
    uint32_t d;

    //Check parameters
    if(df == NULL || key == NULL)
       return (0);

    //Invalid key length?
    if(keylen != 8)
       return (0);

    //Copy the key
    c = padding_message(&c, key + 0);
    d = padding_message(&c, key + 4);

    //Permuted choice 1
    DES_PC1(c, d);

    //Generate the key schedule
    for(i = 0; i < 16; i++)
    {
       //Individual blocks are shifted left
       if(i == 0 || i == 1 || i == 8 || i == 15)
       {
          c = ROL28(c, 1);
          d = ROL28(d, 1);
       }
       else
       {
          c = ROL28(c, 2);
          d = ROL28(d, 2);
       }

       //Permuted choice 2
       context->ks[2 * i] =
          ((c << 4)  & 0x24000000) | ((c << 28) & 0x10000000) |
          ((c << 14) & 0x08000000) | ((c << 18) & 0x02080000) |
          ((c << 6)  & 0x01000000) | ((c << 9)  & 0x00200000) |
          ((c >> 1)  & 0x00100000) | ((c << 10) & 0x00040000) |
          ((c << 2)  & 0x00020000) | ((c >> 10) & 0x00010000) |
          ((d >> 13) & 0x00002000) | ((d >> 4)  & 0x00001000) |
          ((d << 6)  & 0x00000800) | ((d >> 1)  & 0x00000400) |
          ((d >> 14) & 0x00000200) | ((d)       & 0x00000100) |
          ((d >> 5)  & 0x00000020) | ((d >> 10) & 0x00000010) |
          ((d >> 3)  & 0x00000008) | ((d >> 18) & 0x00000004) |
          ((d >> 26) & 0x00000002) | ((d >> 24) & 0x00000001);

       context->ks[2 * i + 1] =
          ((c << 15) & 0x20000000) | ((c << 17) & 0x10000000) |
          ((c << 10) & 0x08000000) | ((c << 22) & 0x04000000) |
          ((c >> 2)  & 0x02000000) | ((c << 1)  & 0x01000000) |
          ((c << 16) & 0x00200000) | ((c << 11) & 0x00100000) |
          ((c << 3)  & 0x00080000) | ((c >> 6)  & 0x00040000) |
          ((c << 15) & 0x00020000) | ((c >> 4)  & 0x00010000) |
          ((d >> 2)  & 0x00002000) | ((d << 8)  & 0x00001000) |
          ((d >> 14) & 0x00000808) | ((d >> 9)  & 0x00000400) |
          ((d)       & 0x00000200) | ((d << 7)  & 0x00000100) |
          ((d >> 7)  & 0x00000020) | ((d >> 3)  & 0x00000011) |
          ((d << 2)  & 0x00000004) | ((d >> 21) & 0x00000002);
    }

    //No error to report
    return NO_ERROR;
 }


void	handle_des(char *message, t_options *opts, char **av)
{
	(void)message;
	(void)opts;
	t_pbkdf df;

	if (!(init_pbkdf(&df, opts, av)))
		return;
	gen_key(&df, opts, message);

//	des_crypt(pt1, buf, schedule);
//	pass = pass && !memcmp(ct1, buf, 16);
//	ft_printf("%d\n", pass);
}
