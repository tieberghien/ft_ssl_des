/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pbkdf.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/15 16:56:26 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/20 13:55:54 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <stdbool.h>

/*
   t_digest_cmd g_cmd[] =
   {
   {"sha1", handle_sha1},
   {0}
   }
   */
/*
void		gen_key(t_pbkdf *pbkdf, t_options *opts, char *pass)
{
	(void)opts;
	//t_arg_opts test;
	//	pbkdf->pass = pass;
	char *buf;

	(void)pass;
	puts((char*)pbkdf->pass);
	puts((char*)pbkdf->salt);
	buf = ssl_pbkdf2((char*)pbkdf->pass, ft_strlen((char*)pbkdf->pass), (char*)pbkdf->salt, ft_strlen((char*)pbkdf->salt), (char*)pbkdf->key, 20, 20);
	ft_printf("%s\n", buf);
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
*/

/*
char	*str_msg_sha(t_sha256_context *c1, t_sha512_context *c2, int d, int w)
{
	char	hash[d + 1];
	char	*s;
	int		i;

	i = -1;
	if (c1)
		while (++i < d)
			hash[i] = (c1->state[i / w] >> ((w - 1 - (i % w)) * 8)) & 0xFF;
	else
		while (++i < d)
			hash[i] = (c2->state[i / w] >> ((w - 1 - (i % w)) * 8)) & 0xFF;
	hash[d] = '\0';
	i = -1;
	if (!(s = (char*)malloc(2 * d + 1)))
		return (NULL);
	s[2 * d] = '\0';
	i = -1;
	while (++i < d)
		convert_to_hex(hash[i], s + 2 * i);
	return (s);
}
*/

void	gen_key(t_pbkdf *pbkdf, t_options *opts, char *pass)
{
	char			*res;
	t_arg_opts		dummy;

	(void)opts;
	if (pbkdf->pass != NULL)
	{
		if (!(res = ft_strjoin((char*)pbkdf->pass, (char*)pbkdf->salt)))
			return;
	}
	else
	{
		if (!(res = ft_strjoin(pass, (char*)pbkdf->salt)))
				return;
	}
	handle_sha1(res, &dummy, (char*)pbkdf->key);
//	c = treat_md5(res, ft_strlen(f->passwd) + 8);
	free(res);
	ft_printf("%s\n", pbkdf->key);
	pbkdf->key[16] = '\0';
	ft_printf("%s\n", pbkdf->key);
//	res = str_msg_sha(c);
//	if (!(f->key = ft_strnew(16)))
//		return (0);
//	ft_memcpy(f->key, res, 16);
	/*
	if (!ft_strcmp(f->mode, "des-ecb") || f->iv)
	{
		free(res);
		return (1);
	}
	if (!(f->iv = ft_strnew(16)))
	{
		free(f->key);
		return (0);
	}
	ft_memcpy(f->iv, res + 16, 16);
	free(res);
	*/
//	return (1);
}
