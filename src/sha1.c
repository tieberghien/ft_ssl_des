/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha1.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/15 13:31:47 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 14:41:02 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static uint32_t g_sines[] =
{
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

void	init_sha1(t_sha1_ctx *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xEFCDAB89;
	ctx->buf[2] = 0x98BADCFE;
	ctx->buf[3] = 0x10325476;
	ctx->buf[4] = 0xc3d2e1f0;
	ctx->bitlen = 0;
	ctx->datalen = 0;
}

static void	padding_message_sha1(t_sha1_ctx *ctx, uint8_t data[])
{
	int	i;
	int	j;

	i = -1;
	j = 0;
	while (++i < 16)
	{
		ctx->message[i] = (data[j] << 24) + (data[j + 1] << 16)
			+ (data[j + 2] << 8) + (data[j + 3]);
		j += 4;
	}
	while (i < 80)
	{
		ctx->message[i] = (ctx->message[i - 3] ^ ctx->message[i - 8]
				^ ctx->message[i - 14] ^ ctx->message[i - 16]);
		ctx->message[i] = (ctx->message[i] << 1) | (ctx->message[i] >> 31);
		i++;
	}
}

static void			append_padding_sha1(t_sha1_ctx *ctx)
{
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
}

static void	sha1_algo(t_sha1_ctx *ctx, uint8_t data[])
{
	int		i;
	uint32_t t;

	padding_message_sha1(ctx, data);
	i = -1;
	while (++i < 5)
		ctx->tmp[i] = ctx->buf[i];
	for (i = 0; i < 20; ++i) {
		t = left_rotation(ctx->tmp[0], 5) + ((ctx->tmp[1] & ctx->tmp[2]) ^ (~ctx->tmp[1] & ctx->tmp[3])) + ctx->tmp[4] + g_sines[0] + ctx->message[i];
		ctx->tmp[4] = ctx->tmp[3];
		ctx->tmp[3] = ctx->tmp[2];
		ctx->tmp[2] = left_rotation(ctx->tmp[1], 30);
		ctx->tmp[1] = ctx->tmp[0];
		ctx->tmp[0] = t;
	}
	for ( ; i < 40; ++i) {
		t = left_rotation(ctx->tmp[0], 5) + (ctx->tmp[1] ^ ctx->tmp[2] ^ ctx->tmp[3]) + ctx->tmp[4] + g_sines[1] + ctx->message[i];
		ctx->tmp[4] = ctx->tmp[3];
		ctx->tmp[3] = ctx->tmp[2];
		ctx->tmp[2] = left_rotation(ctx->tmp[1], 30);
		ctx->tmp[1] = ctx->tmp[0];
		ctx->tmp[0] = t;
	}
	for ( ; i < 60; ++i) {
		t = left_rotation(ctx->tmp[0], 5) + ((ctx->tmp[1] & ctx->tmp[2]) ^ (ctx->tmp[1] & ctx->tmp[3]) ^ (ctx->tmp[2] & ctx->tmp[3]))  + ctx->tmp[4] + g_sines[2] + ctx->message[i];
		ctx->tmp[4] = ctx->tmp[3];
		ctx->tmp[3] = ctx->tmp[2];
		ctx->tmp[2] = left_rotation(ctx->tmp[1], 30);
		ctx->tmp[1] = ctx->tmp[0];
		ctx->tmp[0] = t;
	}
	for ( ; i < 80; ++i) {
		t = left_rotation(ctx->tmp[0], 5) + (ctx->tmp[1] ^ ctx->tmp[2] ^ ctx->tmp[3]) + ctx->tmp[4] + g_sines[3] + ctx->message[i];
		ctx->tmp[4] = ctx->tmp[3];
		ctx->tmp[3] = ctx->tmp[2];
		ctx->tmp[2] = left_rotation(ctx->tmp[1], 30);
		ctx->tmp[1] = ctx->tmp[0];
		ctx->tmp[0] = t;
	}
	i = -1;
	while (++i < 5)
		ctx->buf[i] += ctx->tmp[i];
}

t_sha1_ctx	sha1_update(t_sha1_ctx *ctx, char *data, size_t len)
{
	size_t i;

	i = -1;
	while (++i < len)
	{
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64)
		{
			sha1_algo(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	return (*ctx);
}

void		sha1_final(t_sha1_ctx *ctx, uint8_t hash[])
{
	size_t i;

	(void)hash;
	i = ctx->datalen;
	if (ctx->datalen < 56)
	{
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else
	{
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha1_algo(ctx, ctx->data);
		ft_memset(ctx->data, 0, 56);
	}
	append_padding_sha1(ctx);
	sha1_algo(ctx, ctx->data);
}
