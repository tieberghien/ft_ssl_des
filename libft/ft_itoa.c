/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/13 13:52:28 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/13 18:15:48 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_itoa(int n)
{
	char	*str;
	int		count;
	int		nb;
	int		neg;

	count = 1;
	neg = (n < 0) ? 1 : 0;
	n *= (n > 0) ? -1 : 1;
	nb = n;
	while ((nb /= 10) < 0)
		count++;
	if (!(str = (char*)malloc(sizeof(char) * (count + neg + 1))))
		return (NULL);
	ft_bzero(str, count + neg + 1);
	if (neg == 1)
		str[0] = '-';
	count -= 1 - neg;
	while (count-- >= neg)
	{
		str[count + 1] = (-(n % 10) + '0');
		n /= 10;
	}
	return (str);
}
