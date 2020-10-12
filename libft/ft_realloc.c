/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_realloc.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/08/31 01:21:09 by etieberg          #+#    #+#             */
/*   Updated: 2018/03/29 13:22:50 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_realloc(void *ptr, int size, int len)
{
	void	*new_memory;

	if (!ptr)
		return (ft_malloc_check(size));
	else if (size == 0)
	{
		free(ptr);
		return (NULL);
	}
	else
	{
		new_memory = ft_malloc_check(size);
		ft_memcpy(new_memory, ptr, len);
		free(ptr);
	}
	return (new_memory);
}
