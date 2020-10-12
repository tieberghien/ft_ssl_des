/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_range.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 14:11:57 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/14 23:13:13 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

int		*ft_range(int min, int max)
{
	int	*range;
	int	size;
	int	i;

	i = 0;
	size = max - min - 1;
	range = (int*)malloc(sizeof(int) * (size + 1));
	while (i < max)
	{
		range[i] = min;
		min++;
		i++;
	}
	range[i] = '\0';
	return (range);
}
