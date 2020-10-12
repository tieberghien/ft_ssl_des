/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 18:08:22 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 11:19:23 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void			init_md5(t_md5_ctx *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;
	ctx->bitlen = 0;
	ctx->datalen = 0;
}

static void		md5_loop(t_md5_ctx *ctx, unsigned int i, size_t f, size_t g)
{
	while (++i < 64)
	{
		if (i < 16)
		{
			f = (ctx->tmp[1] & ctx->tmp[2]) | (~ctx->tmp[1] & ctx->tmp[3]);
			g = i;
		}
		else if (i < 32)
		{
			f = (ctx->tmp[3] & ctx->tmp[1]) | (~ctx->tmp[3] & ctx->tmp[2]);
			g = (5 * i + 1) % 16;
		}
		else if (i < 48)
		{
			f = ctx->tmp[1] ^ ctx->tmp[2] ^ ctx->tmp[3];
			g = (3 * i + 5) % 16;
		}
		else
		{
			f = ctx->tmp[2] ^ (ctx->tmp[1] | ~ctx->tmp[3]);
			g = (7 * i) % 16;
		}
		breakdown_md5(ctx, i, f, g);
	}
}

void			md5_algo(t_md5_ctx *ctx, uint8_t data[])
{
	unsigned int	i;
	unsigned int	j;
	size_t			f;
	size_t			g;

	padding_message(ctx, data);
	i = -1;
	while (++i < 4)
		ctx->tmp[i] = ctx->buf[i];
	j = -1;
	f = 0;
	g = 0;
	md5_loop(ctx, j, f, g);
	i = -1;
	while (++i < 4)
		ctx->buf[i] += ctx->tmp[i];
}

t_md5_ctx		md5_update(t_md5_ctx *ctx, char *data, size_t len)
{
	size_t i;

	i = -1;
	while (++i < len)
	{
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64)
		{
			md5_algo(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	return (*ctx);
}

t_md5_ctx		md5_final(t_md5_ctx *ctx, uint8_t hash[])
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
	else if (ctx->datalen >= 56)
	{
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		md5_algo(ctx, ctx->data);
		ft_memset(ctx->data, 0, 56);
	}
	append_padding(ctx);
	md5_algo(ctx, ctx->data);
	return (*ctx);
}
