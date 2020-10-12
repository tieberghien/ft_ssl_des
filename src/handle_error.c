/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   handle_error.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 18:07:51 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 11:39:03 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int		wrong_format(char *cmd, char **error)
{
	while (*error)
	{
		printf("ft_ssl: %s: %s: No such file or directory\n", cmd, *error);
		error++;
	}
	return (-1);
}
