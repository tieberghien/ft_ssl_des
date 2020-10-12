/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 09:21:56 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/13 10:46:44 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "includes/libft.h"

void	*ft_memalloc(size_t size)
{
	void	*mem;

	if (!(mem = (void*)malloc(sizeof(mem) * size)))
		return (NULL);
	ft_bzero(mem, size);
	return (mem);
}
