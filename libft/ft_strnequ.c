/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnequ.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 12:22:18 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/14 21:40:11 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

int		ft_strnequ(char const *s1, char const *s2, size_t n)
{
	int i;

	i = 0;
	if (!s1 || !s2)
		return (0);
	if ((ft_strlen(s1) != ft_strlen(s2)) && n != 0)
		return (0);
	while ((s1[i] != '\0' || s2[i] != '\0') && (size_t)i < n)
	{
		if (s1[i] > s2[i] || s1[i] < s2[i])
			return (0);
		else
			i++;
	}
	return (1);
}
