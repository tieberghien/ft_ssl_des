/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_opts.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 12:08:46 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 11:37:29 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int		parse_opts(char *flags, t_arg_opts *opts)
{
	int i;

	i = 1;
	while (flags && flags[i] && ft_strchr("pqrs", flags[i]))
	{
		if (flags[i] == 'p')
			opts->echo = 1;
		else if (flags[i] == 'q')
			opts->quiet = 1;
		else if (flags[i] == 'r')
			opts->rev = 1;
		else if (flags[i] == 's')
			opts->str = 1;
		i++;
	}
	if (flags && flags[i] != '\0')
	{
		ft_printf("%s -- invalid option\n", flags);
		return (0);
	}
	return (1);
}
