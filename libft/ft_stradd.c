/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_stradd.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/22 16:54:59 by etieberg          #+#    #+#             */
/*   Updated: 2018/03/29 13:14:12 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	**ft_stradd(char **array, char *content, int count)
{
	char	**ret;
	int		i;

	if (content == NULL || count < 0)
		return (NULL);
	if (!(ret = malloc(sizeof(char *) * (count + 1))))
		return (NULL);
	i = -1;
	while (++i < count)
		ret[i] = array[i];
	ret[i] = content;
	if (count != 0)
		free(array);
	return (ret);
}
