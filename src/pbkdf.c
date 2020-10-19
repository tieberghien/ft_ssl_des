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

static void gc_pbkdf2_sha1(const char *P, size_t Plen,
                const char *S, size_t Slen,
                unsigned int c,
                char *DK, size_t dkLen)
{
  unsigned int hLen = 20;
  char U[20];
  char T[20];
  unsigned int u;
  unsigned int l;
  unsigned int r;
  unsigned int i;
  unsigned int k;
  int rc;
  char *tmp;
  size_t tmplen = Slen + 4;
/*
  if (c == 0)
    return GC_PKCS5_INVALID_ITERATION_COUNT;

  if (dkLen == 0)
    return GC_PKCS5_INVALID_DERIVED_KEY_LENGTH;

  if (dkLen > 4294967295U)
    return GC_PKCS5_DERIVED_KEY_TOO_LONG;
*/
  l = ((dkLen - 1) / hLen) + 1;
  r = dkLen - (l - 1) * hLen;

  tmp = malloc (tmplen);
//  if (tmp == NULL)
  //  return GC_MALLOC_ERROR;

  memcpy (tmp, S, Slen);

  for (i = 1; i <= l; i++)
    {
      memset (T, 0, hLen);

      for (u = 1; u <= c; u++)
        {
          if (u == 1)
            {
              tmp[Slen + 0] = (i & 0xff000000) >> 24;
              tmp[Slen + 1] = (i & 0x00ff0000) >> 16;
              tmp[Slen + 2] = (i & 0x0000ff00) >> 8;
              tmp[Slen + 3] = (i & 0x000000ff) >> 0;

              hmac_sha1 (P, Plen, tmp, tmplen, U);
            }
          else
            rc = hmac_sha1(P, Plen, U, hLen, U);

/*
          if (rc != GC_OK)
            {
              free (tmp);
              return rc;
            }
*/
          for (k = 0; k < hLen; k++)
	{
            T[k] ^= U[k];
		printf("%c\n", T[k]);
	}
        }

      memcpy (DK + (i - 1) * hLen, T, i == l ? r : hLen);
    }
  free (tmp);

}

void		gen_key(t_pbkdf *pbkdf, t_options *opts, char *pass)
{
	(void)opts;
	//t_arg_opts test;
//	pbkdf->pass = pass;
//	char *buf;
	(void)pass;
	puts((char*)pbkdf->pass);
	puts((char*)pbkdf->salt);
	gc_pbkdf2_sha1((char*)pbkdf->pass, ft_strlen((char*)pbkdf->pass), (char*)pbkdf->salt, ft_strlen((char*)pbkdf->salt), 20, (char*)pbkdf->key, 16);
/*
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
*/
}
