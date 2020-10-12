/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_intlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/09/13 02:14:42 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 00:40:51 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

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
