/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoabase.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/08/10 17:44:16 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 00:54:50 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_abs(int n)
{
	if (n < 0)
		return (-n);
	else
		return (n);
}

int			ft_intlen(int n, int base)
{
	int		size;

	size = 1;
	if (n < 0 && base == 10)
		size++;
	while (n >= base || n <= -base)
	{
		size++;
		n /= base;
	}
	return (size);
}

char		*ft_itoabase(int n, int base, char *s)
{
	int		i;
	int		size;
	char	itoa_base[BASE];

	if (base < 2 || base > 16)
		return (NULL);
	i = 0;
	ft_strncpy(itoa_base, "0123456789abcdef", base);
	size = ft_intlen(n, base);
	if (n < 0 && base == 10)
		s[i++] = '-';
	s[size] = '\0';
	while (size - 1 >= i)
	{
		s[size - 1] = itoa_base[ft_abs(n % base)];
		size--;
		n /= base;
	}
	return (s);
}
