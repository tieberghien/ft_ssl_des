/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/02 18:42:15 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/01 17:23:50 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strdup(const char *s1)
{
	int		i;
	char	*dst;

	i = 0;
	if (!(dst = (char*)malloc(sizeof(char) * (ft_strlen(s1) + 1))))
		return (0);
	if (dst != NULL)
	{
		while (s1[i] != '\0')
		{
			dst[i] = s1[i];
			i++;
		}
	}
	dst[i] = '\0';
	return (dst);
}
