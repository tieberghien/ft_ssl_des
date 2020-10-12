/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 15:37:00 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/14 20:24:17 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	int				i;
	unsigned int	j;
	size_t			len_dst;

	i = 0;
	len_dst = ft_strlen(dst);
	j = len_dst;
	while (src[i] && j < size - 1)
		dst[j++] = src[i++];
	dst[j] = '\0';
	if (len_dst < size)
		return (len_dst + ft_strlen(src));
	return (size + ft_strlen(src));
}
