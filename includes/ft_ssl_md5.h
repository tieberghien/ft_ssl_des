/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/08 12:06:13 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 14:23:37 by etieberg         ###   ########.fr       */
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
	size_t				size;
	unsigned int		message[16];
	unsigned char		data[64];
	uint32_t			buf[4];
	uint32_t			tmp[4];
	unsigned long long	datalen;
	unsigned long long	bitlen;
}						t_md5_ctx;

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

typedef struct			s_cypher_cmd
{
	char				*cmd;
	void                (*f)(char *, t_arg_opts *);
}						t_cypher_cmd;

typedef struct			s_digest_cmd
{
	char				*cmd;
	void				(*f)(char *, t_arg_opts *);
}						t_digest_cmd;

int						parse_opts(char *flags, t_arg_opts *opts);
int						parse_args(char **av, char *b, t_arg_opts o, int i);
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
void					handle_md5(char *message, t_arg_opts *opts);
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

#endif
