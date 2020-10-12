/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_charcmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/08/31 00:59:26 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 00:56:51 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

short int	ft_charcmp(const char *str, size_t i, char c)
{
	int ret;

	ret = 0;
	if (str[i] != c)
		return (0);
	else
		while (i != 0 && str[i - 1] == '\\')
		{
			i--;
			ret = (ret) ? 0 : 1;
		}
	if (ret)
		return (0);
	return (1);
}
