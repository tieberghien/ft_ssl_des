/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 19:50:28 by etieberg          #+#    #+#             */
/*   Updated: 2017/06/20 17:05:03 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include "includes/libft.h"

int		ft_strcmp(const char *s1, const char *s2)
{
	unsigned char	*ptr1;
	unsigned char	*ptr2;
	int				i;

	i = 0;
	ptr1 = (unsigned char*)s1;
	ptr2 = (unsigned char*)s2;
	while (ptr1[i] != '\0' && ptr2[i] != '\0')
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
