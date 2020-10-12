/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchrr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/21 12:18:00 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/01 20:35:09 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strchrr(char *src, int c)
{
	int		len;

	if (!src)
		return (NULL);
	len = ft_strlen(src);
	while (len && src[len] != c)
		len--;
	src[len] = '\0';
	return (src);
}
