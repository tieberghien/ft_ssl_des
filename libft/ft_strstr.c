/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 20:08:52 by etieberg          #+#    #+#             */
/*   Updated: 2016/11/13 17:28:18 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include "includes/libft.h"

char	*ft_strstr(const char *big, const char *little)
{
	if (little[0] == '\0')
		return ((char*)big);
	while (*big)
	{
		if (ft_strncmp(big, little, ft_strlen(little)) == 0)
			return ((char*)big++);
		big++;
	}
	return (NULL);
}
