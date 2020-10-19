/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pbkdf.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/15 16:56:26 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 19:04:12 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
/*
t_digest_cmd g_cmd[] =
{
	{"sha1", handle_sha1},
	{0}
}
*/
void		gen_key(t_pbkdf *pbkdf, t_options *opts, char *pass)
{
	(void)opts;
	t_arg_opts test;
//	pbkdf->pass = pass;
	char *buf;

	puts((char*)pbkdf->pass);
	puts((char*)pbkdf->salt);
	if (pbkdf->pass != NULL)
	{
		if (!(buf = ft_strjoin((char*)pbkdf->pass, (char*)pbkdf->salt)))
			return;
		handle_sha1(buf, &test, (char*)pbkdf->key);
	}
	else
	{	if (!(buf = ft_strjoin(pass, (char*)pbkdf->salt)))
			return;
		handle_sha1(buf, &test, (char*)pbkdf->key);
	}
	puts((char*)pbkdf->key);
}

