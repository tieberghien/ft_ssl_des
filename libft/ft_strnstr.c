/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 20:23:01 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/14 19:20:01 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strnstr(const char *big, const char *little, size_t len)
{
	size_t len_l;

	len_l = ft_strlen(little);
	if (little[0] == '\0')
		return ((char*)big);
	while (*big && len != 0)
	{
		if (ft_strncmp(big, little, len_l) == 0 && len_l <= len)
			return ((char*)big);
		big++;
		len--;
	}
	return (NULL);
}
