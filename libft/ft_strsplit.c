/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/08 12:41:06 by etieberg          #+#    #+#             */
/*   Updated: 2017/11/02 01:38:00 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

static int	ft_count_words(char const *s, char c)
{
	int		i;
	int		j;

	i = 0;
	j = 0;
	while (s[i])
	{
		while (s[i] && s[i] == c)
			i++;
		while (s[i] && s[i] != c)
			i++;
		if (s[i] != '\0' || s[i] != '\n' || s[i] != '\t' || s[i - 1] != c)
			j++;
	}
	return (j);
}

char		**ft_strsplit(char const *s, char c)
{
	char	**tab;
	int		i;
	int		j;
	int		count;

	i = 0;
	if (!s)
		return (NULL);
	count = ft_count_words(s, c);
	if (!(tab = (char**)malloc(sizeof(char*) * (count + 1))))
		return (NULL);
	while (i < count)
	{
		j = 0;
		while (*s && *s == c)
			s++;
		while (*(s + j) && *(s + j) != c)
			j++;
		*(tab++) = ft_strsub(s, 0, j);
		s = s + j;
		i++;
	}
	*tab = NULL;
	return (tab - count);
}
