/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_charjoin.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/09/11 22:16:39 by etieberg          #+#    #+#             */
/*   Updated: 2017/09/12 22:38:25 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_charjoin(char *s1, const char c)
{
	size_t	size;
	int		i;

	i = 0;
	size = ft_strlen(s1);
	while ((size_t)i < size)
		i++;
	s1[i] = c;
	s1[i + 1] = '\0';
	return (s1);
}
