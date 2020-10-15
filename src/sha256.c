/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 19:06:27 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 14:40:29 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void		init_sha256(t_sha_ctx *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->buf[0] = 0x6a09e667;
	ctx->buf[1] = 0xbb67ae85;
	ctx->buf[2] = 0x3c6ef372;
	ctx->buf[3] = 0xa54ff53a;
	ctx->buf[4] = 0x510e527f;
	ctx->buf[5] = 0x9b05688c;
	ctx->buf[6] = 0x1f83d9ab;
	ctx->buf[7] = 0x5be0cd19;
}

void		sha256_algo(t_sha_ctx *ctx, uint8_t data[])
{
	int			i;
	uint32_t	t1;
	uint32_t	t2;

	padding_message_64(ctx, data);
	i = -1;
	while (++i < 8)
		ctx->tmp[i] = ctx->buf[i];
	i = -1;
	while (++i < 64)
	{
		t1 = first_op(ctx, i);
		t2 = second_op(ctx);
		ctx->tmp[7] = ctx->tmp[6];
		ctx->tmp[6] = ctx->tmp[5];
		ctx->tmp[5] = ctx->tmp[4];
		ctx->tmp[4] = ctx->tmp[3] + t1;
		ctx->tmp[3] = ctx->tmp[2];
		ctx->tmp[2] = ctx->tmp[1];
		ctx->tmp[1] = ctx->tmp[0];
		ctx->tmp[0] = t1 + t2;
	}
	i = -1;
	while (++i < 8)
		ctx->buf[i] += ctx->tmp[i];
}

t_sha_ctx	sha256_update(t_sha_ctx *ctx, char *data, size_t len)
{
	size_t i;

	i = -1;
	while (++i < len)
	{
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64)
		{
			sha256_algo(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	return (*ctx);
}

void		sha256_final(t_sha_ctx *ctx, uint8_t hash[])
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
		sha256_algo(ctx, ctx->data);
		ft_memset(ctx->data, 0, 56);
	}
	append_padding_64(ctx);
	sha256_algo(ctx, ctx->data);
}
