/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 19:17:47 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/01 22:40:45 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strchr(const char *s, int c)
{
	int		i;
	size_t	len;

	i = 0;
	if (!s)
		return (0);
	len = ft_strlen(s);
	if (c == '\0')
		return ((char*)&s[len]);
	while (s[i] != '\0')
	{
		if (s[i] == c)
			return ((char*)&s[i] + 1);
		i++;
	}
	return (0);
}
