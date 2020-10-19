/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/08 12:06:13 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 19:04:09 by etieberg         ###   ########.fr       */
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




int hmac_sha1 (const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf);


#endif
