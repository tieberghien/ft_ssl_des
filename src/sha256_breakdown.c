/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256_breakdown.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 18:41:55 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/11 19:10:41 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static uint32_t	g_sines[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t		first_op(t_sha_ctx *ctx, int i)
{
	uint32_t	res;

	res = ctx->tmp[7] + (right_rotation(ctx->tmp[4], 6)
		^ right_rotation(ctx->tmp[4], 11) ^ right_rotation(ctx->tmp[4], 25))
		+ ((ctx->tmp[4] & ctx->tmp[5]) ^ (~(ctx->tmp[4])
		& ctx->tmp[6])) + g_sines[i] + ctx->message[i];
	return (res);
}

uint32_t		second_op(t_sha_ctx *ctx)
{
	uint32_t res;

	res = (right_rotation(ctx->tmp[0], 2) ^ right_rotation(ctx->tmp[0], 13)
		^ right_rotation(ctx->tmp[0], 22)) + ((ctx->tmp[0] & ctx->tmp[1])
		^ (ctx->tmp[0] & ctx->tmp[2]) ^ (ctx->tmp[1] & ctx->tmp[2]));
	return (res);
}

void			padding_message_64(t_sha_ctx *ctx, uint8_t data[])
{
	int	i;
	int	j;

	i = -1;
	j = 0;
	while (++i < 16)
	{
		ctx->message[i] = (data[j] << 24) | (data[j + 1] << 16)
			| (data[j + 2] << 8) | (data[j + 3]);
		j += 4;
	}
	while (i < 64)
	{
		ctx->message[i] = (right_rotation(ctx->message[i - 2], 17)
			^ right_rotation(ctx->message[i - 2], 19)
			^ (ctx->message[i - 2] >> 10)) + ctx->message[i - 7]
			+ (right_rotation(ctx->message[i - 15], 7)
			^ right_rotation(ctx->message[i - 15], 18)
			^ (ctx->message[i - 15] >> 3)) + ctx->message[i - 16];
		i++;
	}
}

void			append_padding_64(t_sha_ctx *ctx)
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
