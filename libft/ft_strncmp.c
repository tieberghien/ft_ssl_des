/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 21:14:41 by etieberg          #+#    #+#             */
/*   Updated: 2018/03/21 18:38:19 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	unsigned char	*ptr1;
	unsigned char	*ptr2;
	int				i;

	i = 0;
	ptr1 = (unsigned char*)s1;
	ptr2 = (unsigned char*)s2;
	while ((ptr1[i] != '\0' || ptr2[i] != '\0') && (size_t)i < n)
	{
		if (ptr1[i] > ptr2[i])
			return (ptr1[i] - ptr2[i]);
		else if (ptr1[i] < ptr2[i])
			return (ptr1[i] - ptr2[i]);
		else
			i++;
	}
	return (0);
}
