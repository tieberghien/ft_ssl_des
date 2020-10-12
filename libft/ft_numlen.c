/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_numlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 20:08:41 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/11 20:08:43 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_numlen(long long num, int base, size_t size)
{
	int count;

	count = 0;
	base = (base == OCTAL_UPPER) ? OCTAL : base;
	base = (base == HEXA_UPPER) ? HEXA : base;
	if (base != DECIMAL && num < 0)
	{
		if (base == OCTAL)
			return (size * 8 / 3 + 1);
		if (base == HEXA)
			return (size * 8 / 4);
		if (base == BINARY)
			return (size * 8);
	}
	if (base == DECIMAL && num < 0)
		num *= -1;
	while (num)
	{
		num /= base;
		count++;
	}
	return ((count == 0) ? 1 : count);
}

int	ft_unumlen(unsigned long long num)
{
	int count;

	count = 0;
	while (num)
	{
		num /= 10;
		count++;
	}
	return ((count == 0) ? 1 : count);
}
