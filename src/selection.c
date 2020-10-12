/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   selection.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/08 13:17:22 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 11:26:16 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void	handle_md5(char *message, t_arg_opts *opts)
{
	t_md5_ctx		ctx;
	unsigned char	buf[16];

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
