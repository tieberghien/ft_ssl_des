/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_malloc_check.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/07 14:16:00 by etieberg          #+#    #+#             */
/*   Updated: 2018/03/22 17:19:54 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_malloc_check(int size)
{
	void	*buf;

	if (size > 0)
		buf = malloc(size);
	else
		buf = NULL;
	if (!buf)
	{
		ft_putendl_fd("Malloc fail\n", 2);
		exit(1);
	}
	return (buf);
}
