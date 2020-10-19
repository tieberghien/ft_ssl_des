/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   selection.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/08 13:17:22 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 14:57:35 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void	handle_md5(char *message, t_arg_opts *opts, char *key)
{
	t_md5_ctx		ctx;
	unsigned char	buf[16];

	(void)key;
	init_md5(&ctx);
	ctx = md5_update(&ctx, message, ft_strlen(message));
	md5_final(&ctx, buf);
	if (opts->echo && opts->is_stdin)
		ft_printf("%s", message);
	if (opts->is_file && !opts->rev && !opts->quiet)
		ft_printf("%s (%s) = ", "MD5", opts->filename);
	else if (opts->str && !opts->is_stdin && !opts->quiet && !opts->rev)
		ft_printf("%s (\"%s\") = ", "MD5", message);
	rev_endian(ctx.buf[0]);
	rev_endian(ctx.buf[1]);
	rev_endian(ctx.buf[2]);
	rev_endian(ctx.buf[3]);
	ft_printf("\n");
	if (opts->rev && opts->is_file && !opts->quiet)
		ft_printf(" %s\n", opts->filename);
	else if (opts->rev && !opts->is_stdin && !opts->quiet)
		ft_printf(" %s\n", message);
	else
		ft_printf("\n");
}

void	handle_256(char *message, t_arg_opts *opts)
{
	t_sha_ctx	ctx;
	uint8_t		buf[64];

	init_sha256(&ctx);
	ctx = sha256_update(&ctx, message, strlen(message));
	sha256_final(&ctx, buf);
	if (opts->echo && opts->is_stdin)
		ft_printf("%s", message);
	if (opts->is_file && !opts->rev && !opts->quiet)
		ft_printf("%s (%s) = ", "SHA256", opts->filename);
	else if (opts->str && !opts->is_stdin && !opts->quiet && !opts->rev)
		ft_printf("%s (\"%s\") = ", "SHA256", message);
	ft_printf("%08x%08x%08x%08x%08x%08x%08x%08x", ctx.buf[0], ctx.buf[1],
		ctx.buf[2], ctx.buf[3], ctx.buf[4], ctx.buf[5], ctx.buf[6], ctx.buf[7]);
	if (opts->rev && opts->is_file && !opts->quiet)
		ft_printf(" %s\n", opts->filename);
	else if (opts->rev && !opts->is_stdin && !opts->quiet)
		ft_printf(" %s\n", message);
	else
		ft_printf("\n");
}

void	handle_224(char *message, t_arg_opts *opts)
{
	t_sha_ctx	ctx;
	uint8_t		buf[64];

	init_sha224(&ctx);
	ctx = sha256_update(&ctx, message, strlen(message));
	sha256_final(&ctx, buf);
	if (opts->echo && opts->is_stdin)
		ft_printf("%s", message);
	if (opts->is_file && !opts->rev && !opts->quiet)
		ft_printf("%s (%s) = ", "SHA224", opts->filename);
	else if (opts->str && !opts->is_stdin && !opts->quiet && !opts->rev)
		ft_printf("%s (\"%s\") = ", "SHA244", message);
	ft_printf("%08x%08x%08x%08x%08x%08x%08x", ctx.buf[0], ctx.buf[1],
			ctx.buf[2], ctx.buf[3], ctx.buf[4], ctx.buf[5], ctx.buf[6]);
	if (opts->rev && opts->is_file && !opts->quiet)
		ft_printf(" %s\n", opts->filename);
	else if (opts->rev && !opts->is_stdin && !opts->quiet)
		ft_printf(" %s\n", message);
	else
		ft_printf("\n");
}
static void sha1_xor(t_sha1_ctx *ctx, t_sha1_ctx *tmp)
{
  ctx->buf[0] ^= tmp->buf[0];
  ctx->buf[1] ^= tmp->buf[1];
  ctx->buf[2] ^= tmp->buf[2];
  ctx->buf[3] ^= tmp->buf[3];
  ctx->buf[4] ^= tmp->buf[4];
}

#define IPAD 0x36
#define OPAD 0x5c

void *
memxor (void *restrict dest, const void *restrict src, size_t n)
{
  char const *s = src;
  char *d = dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}



int
hmac_sha1 (const void *key, size_t keylen,
           const void *in, size_t inlen, void *resbuf)
{
  t_sha1_ctx inner;
  t_sha1_ctx outer;
  uint8_t buf[20];
  char block[64];
  char innerhash[20];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */
  if (keylen > 64)
    {
      t_sha1_ctx ctx;

      	init_sha1(&ctx);
	ctx = sha1_update(&ctx, (char*)key, keylen);
	sha1_final(&ctx, buf);

      key = buf;
      keylen = 20;
    }
  /* Compute INNERHASH from KEY and IN.  */

  init_sha1(&inner);

  memset (block, IPAD, sizeof (block));
  memxor (block, key, keylen);

	inner = sha1_update(&inner, (char*)in, inlen);
//  sha1_process_bytes (in, inlen, &inner);
	sha1_final(&inner, (uint8_t*)innerhash);
//  sha1_finish_ctx (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  init_sha1(&outer);

  memset (block, OPAD, sizeof (block));
  memxor (block, key, keylen);

	outer = sha1_update(&outer, innerhash, 20);
	 //  sha1_process_bytes (in, inlen, &inner);
         sha1_final(&outer, resbuf);

	ft_printf("%08X%08X\n", outer.buf[0], outer.buf[1]);
/*
  sha1_process_block (block, 64, &outer);
  sha1_process_bytes (innerhash, 20, &outer);

  sha1_finish_ctx (&outer, resbuf);
*/
  return 0;
}



void	handle_sha1(char *message, t_arg_opts *opts, char *key)
{
	t_sha1_ctx	ctx;
	t_sha1_ctx	copy;
	uint8_t		buf[24];

	int i = -1;
	(void)opts;
	init_sha1(&ctx);
	ctx = sha1_update(&ctx, message, strlen(message));
	sha1_final(&ctx, buf);
	sprintf(key, "%08x%08x%08x%08x%08x", ctx.buf[0], ctx.buf[1], ctx.buf[2], ctx.buf[3], ctx.buf[4]);
	copy = ctx;
	while (++i < 20)
	{
		copy = sha1_update(&copy, key, strlen(message));
		sha1_final(&copy, (uint8_t*)key);
		sha1_xor(&ctx, &copy);
	}
	sprintf(key, "%08X%08X", ctx.buf[0], ctx.buf[1]);
	/*
	if (opts->echo && opts->is_stdin)
		ft_printf("%s", message);
	if (opts->is_file && !opts->rev && !opts->quiet)
		ft_printf("%s (%s) = ", "SHA1", opts->filename);
	else if (opts->str && !opts->is_stdin && !opts->quiet && !opts->rev)
		ft_printf("%s (\"%s\") = ", "SHA1", message);
	ft_printf("%08x%08x%08x%08x%08x", ctx.buf[0], ctx.buf[1],
		ctx.buf[2], ctx.buf[3], ctx.buf[4]);
	if (opts->rev && opts->is_file && !opts->quiet)
		ft_printf(" %s\n", opts->filename);
	else if (opts->rev && !opts->is_stdin && !opts->quiet)
		ft_printf(" %s\n", message);
	else
		ft_printf("\n");
	*/
}
