/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/13 19:31:40 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 09:49:29 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

t_list	*ft_lstnew(void const *content, int content_size)
{
	t_list	*lst;

	lst = ft_malloc_check(sizeof(t_list));
	lst->content = ft_malloc_check(content_size + 1);
	if (!content)
	{
		free(lst->content);
		lst->content = NULL;
		lst->content_size = 0;
	}
	else
	{
		ft_memcpy(lst->content, content, content_size + 1);
		lst->content_size = content_size;
	}
	lst->next = NULL;
	return (lst);
}
