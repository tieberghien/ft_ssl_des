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
void		gen_key(t_pbkdf *pbkdf, t_arg_opts *opts, char *pass)
{
	(void)pbkdf;
//	pbkdf->pass = pass;
	handle_sha1(pass, opts);
}:wq

