/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/12 21:13:08 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/14 23:05:38 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes/libft.h"

char	*ft_strtrim(char const *s)
{
	char	*new;
	size_t	i;
	size_t	n;

	i = 0;
	n = 0;
	if (!s)
		return (0);
	while (s[i] == ' ' || s[i] == '\t' || s[i] == '\n')
		i++;
	if (!s[i])
		return (ft_strnew(1));
	n = ft_strlen(s) - 1;
	while (s[n] == ' ' || s[n] == '\t' || s[n] == '\n')
		n--;
	n = n - i + 1;
	if (!(new = ft_strsub(s, i, n)))
		return (NULL);
	return (new);
}
