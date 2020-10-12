/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_arraydup.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/01 17:00:28 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 09:00:37 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char		**ft_arraydup(char **original)
{
	char	**new_environ;
	size_t	original_size;
	size_t	i;

	i = 0;
	original_size = (original == NULL) ? 0 : ft_arraylen(original);
	if (!(new_environ = (char**)malloc(sizeof(char*) * original_size + 1)))
		exit(0);
	while (i != original_size)
	{
		new_environ[i] = ft_strdup(original[i]);
		i++;
	}
	new_environ[original_size] = NULL;
	return (new_environ);
}
