/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 20:17:46 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/13 14:51:08 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

int		ft_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *ptr1;
	const unsigned char *ptr2;
	int					i;

	i = 0;
	ptr1 = s1;
	ptr2 = s2;
	if (n == 0)
		return (0);
	while (n--)
	{
		if (ptr1[i] > ptr2[i] || ptr1[i] < ptr2[i])
			return (ptr1[i] - ptr2[i]);
		i++;
	}
	return (0);
}
