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

int		parse_opts(char *flags, t_options *opts)
{
	int i;

	i = 1;
	while (flags && flags[i] && ft_strchr("adeikopsv", flags[i]))
	{
		if (flags[i] == 'a')
			opts->base = 1;
		else if (flags[i] == 'd')
			opts->dec = 1;
		else if (flags[i] == 'e')
			opts->enc = 1;
		else if (flags[i] == 'i')
			opts->input = i;
		else if (flags[i] == 'k')
			opts->key = i;
		else if (flags[i] == 'o')
			opts->output = i;
		else if (flags[i] == 'p')
			opts->pass = i;
		else if (flags[i] == 's')
			opts->salt = i;
		else if (flags[i] == 'v')
			opts->iv = i;
		i++;
	}
	if (flags && flags[i] != '\0')
	{
		ft_printf("%s -- invalid option\n", flags);
		return (0);
	}
	return (1);
}

int		init_pbkdf(t_pbkdf *pbkdf, t_options *opts, char **av)
{
	if (opts->pass)
	{
		if (av[opts->pass + 2] && av[opts->pass + 2])
			pbkdf->pass = (const uint8_t *)ft_strdup(av[opts->pass + 2]);
		else
		{
			ft_putendl("missing source argument for -p");
			return (0);
		}
	}
	if (opts->input)
	{
		if (av[opts->input + 2])
			pbkdf->input = (const uint8_t *)ft_strdup(av[opts->input + 2]);
		else
			ft_putendl("missing file argument for -i");
	}
	else if (opts->output)
	{
		if (av[opts->input + 2])
			pbkdf->output = (const uint8_t *)ft_strdup(av[opts->output + 2]);
		else
			ft_putendl("missing file argument for -o");
	}
	return (1);
}

int		invalid_opts(char *cmd, t_options *opts)
{
	if (ft_strncmp("base64", cmd, 6) == 0 && (opts->key || opts->pass
		|| opts->salt || opts->base || opts->iv))
	{
		ft_putstr("base64: invalid option --\n");
		return (0);
	}
	return (1);
}
