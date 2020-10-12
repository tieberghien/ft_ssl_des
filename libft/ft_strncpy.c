/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/09 15:13:05 by etieberg          #+#    #+#             */
/*   Updated: 2017/10/11 17:38:01 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strncpy(char *dst, const char *src, size_t len)
{
	size_t	len_src;
	int		i;

	len_src = ft_strlen(src);
	i = 0;
	while (src[i] != '\0' && (unsigned int)i != len)
	{
		dst[i] = src[i];
		i++;
	}
	if (len_src < len)
	{
		while (len_src++ < len)
		{
			dst[i] = '\0';
			i++;
		}
	}
	return (dst);
}
