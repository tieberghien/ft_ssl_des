/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 20:17:18 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/13 20:15:24 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	len--;
	if (dst >= src && dst <= src + len)
	{
		while (len > 0)
		{
			*(unsigned char*)(dst + len) = *(unsigned char*)(src + len);
			len--;
		}
		*(unsigned char*)dst = *(unsigned char*)src;
	}
	else
	{
		len++;
		dst = ft_memcpy(dst, src, len);
	}
	return (dst);
}
