/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/08 12:06:13 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/20 14:30:05 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_MD5_H
# define FT_SSL_MD5_H

# include <fcntl.h>
# include <unistd.h>
# include <stdlib.h>
# include "libft.h"
# include "ft_printf.h"

# define USAGE "usage: ft_ssl command [command opts] [command args]\n"

static const int sbox1[64] = 
{
	14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
	 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
	 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
	15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13
};

static const int sbox2[64] = 
{
	15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
	 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
	 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
	13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9
};

static const int sbox3[64] = 
{
	10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
	13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
	13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
	 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12
};

static const int sbox4[64] = 
{
	 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
	13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
	10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
	 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14
};

static const int sbox5[64] = 
{
	 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
	14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
	 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
	11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3
};

static const int sbox6[64] = 
{
	12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11,
	10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
	 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
	 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13
};

static const int sbox7[64] = 
{
	 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
	13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
	 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
	 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12
};

static const int sbox8[64] = 
{
	13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
	 1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
	 7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
	 2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11
};

typedef struct			s_md5_ctx
{
	unsigned int		message[16];
	unsigned char		data[64];
	uint32_t			buf[4];
	uint32_t			tmp[4];
	unsigned long long	datalen;
	unsigned long long	bitlen;
}						t_md5_ctx;

typedef struct			s_sha1_ctx
{
	unsigned int		message[80];
	uint8_t				data[64];
	uint32_t			buf[5];
	uint32_t			tmp[5];
	unsigned int		datalen;
	unsigned long long	bitlen;
}						t_sha1_ctx;

typedef struct			s_sha_ctx
{
	unsigned int		message[64];
	uint8_t				data[64];
	uint32_t			buf[8];
	uint32_t			tmp[8];
	unsigned int		datalen;
	unsigned long long	bitlen;
}						t_sha_ctx;

typedef struct			s_arg_opts
{
	int					echo;
	int					quiet;
	int					rev;
	int					str;
	int					is_stdin;
	int					is_file;
	char				*filename;
	int					n_opts;
}						t_arg_opts;

typedef struct			s_options
{
	int			dec;
	int			enc;
	int			input;
	int			output;
	int			base;
	int			key;
	int			pass;
	int			salt;
	int			iv;
	int			is_stdin;
	int			n_opts;
}				t_options;

typedef struct			s_cypher_cmd
{
	char				*cmd;
	void                (*f)(char *, t_options *, char **av);
}						t_cypher_cmd;

typedef struct			s_digest_cmd
{
	char				*cmd;
	void				(*f)(char *, t_arg_opts *);
}						t_digest_cmd;

typedef struct			s_pbkdf
{
	t_digest_cmd		hmac;
	size_t				hlen;
	const uint8_t		*pass;
	size_t				plen;
	const uint8_t		*salt;
	size_t				slen;
	uint8_t				key[32];
	size_t				klen;
	unsigned int		rounds;
	const uint8_t		*input;
	const uint8_t		*output;
}						t_pbkdf;

int						parse_opts(char *flags, t_options *opts, int i);
int						parse_args(char **av, char *b, t_options o, int i);
char					*get_file(char *file);
char					*get_stdin(void);
void					md5_algo(t_md5_ctx *ctx, uint8_t data[]);
void					padding_message(t_md5_ctx *ctx, uint8_t data[]);
void					append_padding(t_md5_ctx *ctx);
void					breakdown_md5(t_md5_ctx *ctx, int i, int f, int g);
uint32_t				left_rotation(uint32_t x, int n);
uint64_t				left_rotation_64(uint64_t x, int n);
uint32_t				right_rotation(uint32_t x, int n);
uint64_t				right_rotation_64(uint64_t x, int n);
void					rev_endian(unsigned n);
void					handle_md5(char *message, t_arg_opts *opts, char *key);
void					init_md5(t_md5_ctx *ctx);
t_md5_ctx				md5_update(t_md5_ctx *ctx, char *data, size_t len);
t_md5_ctx				md5_final(t_md5_ctx *ctx, uint8_t hash[]);
void					handle_256(char *message, t_arg_opts *opts);
void					init_sha256(t_sha_ctx *ctx);
uint32_t				first_op(t_sha_ctx *ctx, int i);
uint32_t				second_op(t_sha_ctx *ctx);
void					sha256_algo(t_sha_ctx *ctx, uint8_t data[]);
void					padding_message_64(t_sha_ctx *ctx, uint8_t data[]);
void					append_padding_64(t_sha_ctx *ctx);
t_sha_ctx				sha256_update(t_sha_ctx *ctx, char *data, size_t len);
void					sha256_final(t_sha_ctx *ctx, uint8_t data[]);
void					handle_224(char *message, t_arg_opts *opts);
void					init_sha224(t_sha_ctx *ctx);
int						wrong_format(char *cmd, char **error);
int					invalid_opts(char *cmd, t_options *opts);
void					handle_sha1(char *message, t_arg_opts *opts, char *key);
void					init_sha1(t_sha1_ctx *ctx);
t_sha1_ctx				sha1_update(t_sha1_ctx *ctx, char *data, size_t len);
void					sha1_final(t_sha1_ctx *ctx, uint8_t hash[]);
void					base64(char *message, t_options *opts, char **av);
void					base64_encode(char *message, t_options *opts);
void					base64_decode(char *cypher, t_options *opts);
void					gen_key(t_pbkdf *pbkdf, t_options *opts, char *pass);
void					handle_des(char *message, t_options *opts, char **av);
int             init_pbkdf(t_pbkdf *pbkdf, t_options *opts, char **av);
uint32_t    bitnum(uint32_t x[], int m, int n);
uint32_t    bitnumintr(uint32_t x, int m, int n);
uint32_t    bitnumintl(uint32_t x, int m, int n);



int hmac_sha1 (const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf);


#endif
